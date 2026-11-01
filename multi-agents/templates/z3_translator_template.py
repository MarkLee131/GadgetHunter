"""
json2z3.py
    usage:  python json2z3.py summary.json  > out.py
             python out.py
summary.json  is the LLM-emitted micro-IR ({vars, flow, guard})
"""
import json, sys
from textwrap import dedent
from tools.analysis.outcomes import InconclusiveAnalysis

# ---------- utility for generating runtime code ----------
def gen_var_init():
    return dedent("""\
        # Enhanced Z3 setup for Java deserialization constraints
        Obj = DeclareSort('Obj')
        ClassName = DeclareSort('ClassName') 
        Module = DeclareSort('Module')
        Package = DeclareSort('Package')
        
        # Null objects
        NullO = Const('null', Obj)
        NULL_S = StringVal("")
        
        # Type system functions
        TypeF = Function('Type', Obj, StringSort())
        TypeOf = Function('TypeOf', Obj, ClassName)
        # Cast feasibility (cast_compatible) is decided against the real class
        # hierarchy by the JVM subtype oracle in path_constraint_agent, before
        # translation; the translator needs no subtype relation here.
        NotAnonymous = Function('NotAnonymous', StringSort(), BoolSort())

        # Data-flow is modelled as taint propagation (value-flow), NOT object
        # identity / must-alias: a flow edge must not force the two endpoints to
        # be the same typed object.
        Tainted = Function('Tainted', Obj, BoolSort())

        # Runtime feasibility functions (NEW)
        Serializable = Function('Serializable', ClassName, BoolSort())
        ReflectionAccessible = Function('ReflectionAccessible', ClassName, StringSort(), BoolSort())
        ModuleOpens = Function('ModuleOpens', Module, Package, BoolSort())
        ClassAvailable = Function('ClassAvailable', ClassName, BoolSort())

        s = Solver()
        z = {}   # cache
        def v(name, *, srt='obj'):
            if name not in z:
                if srt == 'str':
                    z[name] = Const(name, StringSort())
                elif srt == 'int':
                    z[name] = Const(name, IntSort())
                elif srt == 'class':
                    z[name] = Const(name, ClassName)
                elif srt == 'module':
                    z[name] = Const(name, Module)
                elif srt == 'package':
                    z[name] = Const(name, Package)
                elif srt == 'set':
                    # Collections/maps modelled with the SMT theory of arrays
                    # (Set(Obj) = Array(Obj, Bool)); membership is IsMember.
                    z[name] = Const(name, SetSort(Obj))
                else:
                    z[name] = Const(name, Obj)
            return z[name]
    """)

def emit_var_constraint(name, cons):
    import re as _re
    if not isinstance(cons, str):
        return f"# unknown var-constraint (non-string): {cons}"
    cons = cons.strip()
    if cons == "nonnull":
        return f"s.add(v('{name}') != NullO if v('{name}').sort()==Obj else v('{name}', srt='str') != NULL_S)"
    elif cons.startswith("=="):
        val = cons[2:].strip().strip('"')
        return f"s.add(v('{name}', srt='str') == StringVal('{val}'))"
    elif cons in ["StringSort", "Obj", "IntSort", "BoolSort"]:
        # Type declarations - handled in variable creation, no constraint needed
        return f"# {name} declared as {cons}"
    else:
        # Type constraints mirror the type(x,Cls) guard: assert the runtime type.
        # Accept "instanceof Cls" or a bare fully-qualified class name.
        cls = None
        if cons.startswith("instanceof "):
            cls = cons[len("instanceof "):].strip()
        elif "." in cons and _re.fullmatch(r'[A-Za-z_][\w.$]*', cons):
            cls = cons
        if cls:
            return f"s.add(TypeF(v('{name}')) == StringVal('{sanitize_class_name(cls)}'))"
        return f"# unknown var-constraint: {cons}"

# ---------- main translator ----------
def generate_z3_script(j):
    """Original function for backward compatibility"""
    return generate_z3_script_from_json(j)

def generate_z3_script_from_json(j):
    """
    Generate Z3 script from JSON constraints with runtime feasibility support
    
    Args:
        j: JSON constraints dict with vars, flow, guard, runtime keys
        
    Returns:
        Complete Z3 script as string
    """
    # Validate input
    if not isinstance(j, dict) or any(not isinstance(j.get(key), list) for key in ("vars", "flow", "guard", "runtime")):
        raise InconclusiveAnalysis("Expected vars, flow, guard, and runtime lists")
    
    out = ["from z3 import *", "", gen_var_init()]
    
    # Track statistics for debugging
    stats = {"vars_processed": 0, "vars_skipped": 0, "flow_processed": 0, "flow_skipped": 0, 
             "guard_processed": 0, "guard_skipped": 0, "runtime_processed": 0, "runtime_skipped": 0}

    # Process vars with validation
    vars_list = j.get("vars", [])
    if not isinstance(vars_list, list):
        out.append(f"# warning: vars is not a list, got {type(vars_list)}")
        vars_list = []
    
    for v in vars_list:
        try:
            if not isinstance(v, dict):
                out.append(f"# skipped non-dict var: {v}")
                stats["vars_skipped"] += 1
                continue
            
            if "name" not in v or "constraint" not in v:
                out.append(f"# skipped malformed var (missing name/constraint): {v}")
                stats["vars_skipped"] += 1
                continue
                
            var_name = str(v["name"]).strip()
            var_constraint = str(v["constraint"]).strip()
            
            if not var_name or not var_constraint:
                out.append(f"# skipped empty var name/constraint: {v}")
                stats["vars_skipped"] += 1
                continue
            
            constraint_line = emit_var_constraint(var_name, var_constraint)
            out.append(constraint_line)
            if constraint_line.startswith("# unknown"):
                stats["vars_skipped"] += 1
            else:
                stats["vars_processed"] += 1
            
        except Exception as e:
            out.append(f"# error processing var {v}: {e}")
            stats["vars_skipped"] += 1

    # Process flow constraints with validation
    flow_list = j.get("flow", [])
    if not isinstance(flow_list, list):
        out.append(f"# warning: flow is not a list, got {type(flow_list)}")
        flow_list = []
    
    for f in flow_list:
        try:
            if not isinstance(f, str):
                out.append(f"# skipped non-string flow: {f}")
                stats["flow_skipped"] += 1
                continue
                
            f = f.strip()
            if not f or "->" not in f:
                out.append(f"# skipped malformed flow (no ->): {f}")
                stats["flow_skipped"] += 1
                continue
                
            parts = [p.strip() for p in f.split("->")]
            if len(parts) != 2:
                out.append(f"# skipped malformed flow (wrong parts count): {f}")
                stats["flow_skipped"] += 1
                continue
                
            src, dst = parts
            if not src or not dst:
                out.append(f"# skipped flow with empty src/dst: {f}")
                stats["flow_skipped"] += 1
                continue
                
            # Sanitize variable names
            src = sanitize_var_name(src)
            dst = sanitize_var_name(dst)

            # Taint propagation, not identity: flow carries attacker-control
            # along the edge without aliasing the endpoints' types/values.
            out.append(f"s.add(Implies(Tainted(v('{src}')), Tainted(v('{dst}'))))")
            stats["flow_processed"] += 1
            
        except Exception as e:
            out.append(f"# error processing flow {f}: {e}")
            stats["flow_skipped"] += 1

    # Process guard constraints with validation
    guard_list = j.get("guard", [])
    if not isinstance(guard_list, list):
        out.append(f"# warning: guard is not a list, got {type(guard_list)}")
        guard_list = []
    
    for g in guard_list:
        try:
            if not isinstance(g, str):
                out.append(f"# skipped non-string guard: {g}")
                stats["guard_skipped"] += 1
                continue
                
            g = g.strip()
            if not g:
                out.append(f"# skipped empty guard")
                stats["guard_skipped"] += 1
                continue
            
            processed = process_guard_constraint(g, out)
            if processed:
                stats["guard_processed"] += 1
            else:
                stats["guard_skipped"] += 1
                
        except Exception as e:
            out.append(f"# error processing guard {g}: {e}")
            stats["guard_skipped"] += 1
    
    out.append("")
    
    # Process runtime constraints (NEW)
    runtime_list = j.get("runtime", [])
    if not isinstance(runtime_list, list):
        out.append(f"# warning: runtime is not a list, got {type(runtime_list)}")
        runtime_list = []
    
    for r in runtime_list:
        try:
            if not isinstance(r, str):
                out.append(f"# skipped non-string runtime: {r}")
                stats["runtime_skipped"] += 1
                continue
                
            r = r.strip()
            if not r:
                out.append(f"# skipped empty runtime")
                stats["runtime_skipped"] += 1
                continue
            
            processed = process_runtime_constraint(r, out)
            if processed:
                stats["runtime_processed"] += 1
            else:
                stats["runtime_skipped"] += 1
                
        except Exception as e:
            out.append(f"# error processing runtime {r}: {e}")
            stats["runtime_skipped"] += 1
    
    # Add statistics comment
    out.append("")
    out.append(f"# Enhanced Statistics: vars({stats['vars_processed']}/{stats['vars_processed']+stats['vars_skipped']}), " +
               f"flow({stats['flow_processed']}/{stats['flow_processed']+stats['flow_skipped']}), " +
               f"guard({stats['guard_processed']}/{stats['guard_processed']+stats['guard_skipped']}), " +
               f"runtime({stats['runtime_processed']}/{stats['runtime_processed']+stats['runtime_skipped']})")

    skipped = sum(value for key, value in stats.items() if key.endswith("_skipped"))
    if skipped:
        raise InconclusiveAnalysis(f"Translator cannot represent {skipped} constraint(s); refusing a partial formula")
    if not any(line.startswith("s.add(") for line in out):
        raise InconclusiveAnalysis("No constraints were emitted")
    out += ["", "print('Constraint count:', len(s.assertions()))", "result = s.check()",
            "print('Enhanced Z3 Result:', result)", "if result == sat:",
            "    print('Logical Model:', s.model())", "elif result == unknown:",
            "    print('Reason:', s.reason_unknown())"]

    return "\n".join(out)

def process_guard_constraint(g, out):
    """
    Process a single guard constraint with robust error handling
    
    Args:
        g: Guard constraint string
        out: Output list to append processed constraint
        
    Returns:
        True if processed successfully, False otherwise
    """
    try:
        if g.startswith("nonnull("):
            x = g[8:-1].strip()
            if not x:
                out.append(f"# skipped malformed guard: {g}")
                return False
            x = sanitize_var_name(x)
            out.append(f"s.add(v('{x}') != NullO if v('{x}').sort()==Obj else v('{x}', srt='str') != NULL_S)")
            return True
            
        elif g.startswith("type("):
            inner = g[5:-1]
            if "," not in inner:
                out.append(f"# skipped malformed type guard: {g}")
                return False
            x, cls = [p.strip() for p in inner.split(",", 1)]
            if not x or not cls:
                out.append(f"# skipped type guard with empty var/class: {g}")
                return False
            x = sanitize_var_name(x)
            cls = sanitize_class_name(cls)
            out.append(f"s.add(TypeF(v('{x}')) == StringVal('{cls}'))")
            return True
            
        elif g.startswith("cmp("):
            import re as _re
            inner = g[4:-1]
            # Detect the comparison operator; check two-character operators first.
            op = next((c for c in ("==", "!=", ">=", "<=", ">", "<") if c in inner), None)
            if op is None:
                out.append(f"# skipped malformed cmp guard: {g}")
                return False
            left, right = [p.strip() for p in inner.split(op, 1)]
            if not left or not right:
                out.append(f"# skipped cmp guard with empty side: {g}")
                return False
            left = sanitize_var_name(left)
            rstr = right.strip('"\'')
            if _re.fullmatch(r'-?\d+', rstr):
                # Numeric comparison: model the left side as an integer.
                out.append(f"s.add(v('{left}', srt='int') {op} IntVal({int(rstr)}))")
                return True
            if op in ("==", "!="):
                # String (in)equality against a literal.
                out.append(f"s.add(v('{left}', srt='str') {op} StringVal('{rstr}'))")
                return True
            out.append(f"# skipped cmp guard with non-numeric ordering operand: {g}")
            return False
            
        elif g.startswith("range("):
            import re as _re
            inner = g[6:-1].strip()
            # Split keeping the operators: "0<=len<10" -> ['0','<=','len','<','10'];
            # "0<=length" -> ['0','<=','length'].
            toks = _re.split(r'\s*(<=|<)\s*', inner)
            is_int = lambda t: bool(_re.fullmatch(r'-?\d+', t))
            if len(toks) == 3:
                a, op, b = toks[0].strip(), toks[1], toks[2].strip()
                if is_int(a) and not is_int(b):          # bound OP var
                    var = sanitize_var_name(b)
                    out.append(f"s.add(IntVal({int(a)}) {op} v('{var}', srt='int'))")
                    return True
                if is_int(b) and not is_int(a):          # var OP bound
                    var = sanitize_var_name(a)
                    out.append(f"s.add(v('{var}', srt='int') {op} IntVal({int(b)}))")
                    return True
                out.append(f"# skipped range guard with ambiguous operands: {g}")
                return False
            if len(toks) == 5 and is_int(toks[0].strip()) and is_int(toks[4].strip()):
                low, op1, var, op2, high = toks
                var = sanitize_var_name(var.strip())
                out.append(f"s.add(IntVal({int(low.strip())}) {op1} v('{var}', srt='int'))")
                out.append(f"s.add(v('{var}', srt='int') {op2} IntVal({int(high.strip())}))")
                return True
            out.append(f"# skipped malformed range guard: {g}")
            return False
                
        elif g.startswith("contains(") or g.startswith("not_contains("):
            # Collection/map membership via the SMT theory of arrays (Set = Array(Obj,Bool)).
            neg = g.startswith("not_contains(")
            inner = g[g.index("(") + 1:-1]
            if "," not in inner:
                out.append(f"# skipped malformed membership guard: {g}")
                return False
            coll, elem = [p.strip() for p in inner.split(",", 1)]
            if not coll or not elem:
                out.append(f"# skipped membership guard with empty operand: {g}")
                return False
            # A collection has its own set view ('<name>__set') so it never clashes
            # with an object-sorted use of the same name (e.g. nonnull(coll)).
            coll = sanitize_var_name(coll) + "__set"
            elem = sanitize_var_name(elem)
            mem = f"IsMember(v('{elem}', srt='obj'), v('{coll}', srt='set'))"
            out.append(f"s.add({'Not(' + mem + ')' if neg else mem})")
            return True

        elif g.startswith("empty(") or g.startswith("nonempty("):
            neg = g.startswith("nonempty(")
            inner = g[g.index("(") + 1:-1].strip()
            if not inner:
                out.append(f"# skipped empty guard with no operand: {g}")
                return False
            coll = sanitize_var_name(inner) + "__set"
            eq = f"v('{coll}', srt='set') == EmptySet(Obj)"
            out.append(f"s.add({'Not(' + eq + ')' if neg else eq})")
            return True

        elif g in ("always_throw", "early_return"):
            out.append("s.add(False)  # path pruned")
            return True
            
        else:
            out.append(f"# unknown guard pattern: {g}")
            return False
            
    except Exception as e:
        out.append(f"# error processing guard {g}: {e}")
        return False

def sanitize_var_name(name):
    """
    Sanitize variable name for Z3
    
    Args:
        name: Variable name string
        
    Returns:
        Sanitized variable name
    """
    import re
    # Remove non-alphanumeric characters except underscore
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', str(name))
    # Ensure it starts with letter or underscore
    if sanitized and not sanitized[0].isalpha() and sanitized[0] != '_':
        sanitized = '_' + sanitized
    return sanitized if sanitized else 'unknown_var'

def sanitize_class_name(name):
    """
    Sanitize class name for Z3

    Args:
        name: Class name string

    Returns:
        Sanitized class name
    """
    import re
    # Allow dots for package names
    sanitized = re.sub(r'[^a-zA-Z0-9_.]', '_', str(name))
    return sanitized if sanitized else 'UnknownClass'

def _type_expr(tok):
    """Render a cast/type operand as a Z3 type-name expression.

    A class literal (qualified name, or a single CamelCase identifier) becomes
    a StringVal; a variable reference (this, argN, field.x, lowercase name)
    becomes TypeF(v(name)) so it links to type()/typed-var constraints.
    """
    import re
    tok = str(tok).strip()
    if ('.' in tok and re.fullmatch(r'[A-Za-z_][\w.$]*', tok)) or re.fullmatch(r'[A-Z]\w*', tok):
        return f"StringVal('{sanitize_class_name(tok)}')"
    return f"TypeF(v('{sanitize_var_name(tok)}'))"

def process_runtime_constraint(r, out):
    """
    Process a single runtime constraint (NEW)
    
    Args:
        r: Runtime constraint string
        out: Output list to append processed constraint
        
    Returns:
        True if processed successfully, False otherwise
    """
    try:
        if r.startswith("reflection_accessible("):
            inner = r[22:-1]
            if "." in inner:
                class_name, field_name = inner.rsplit(".", 1)
                class_name = sanitize_class_name(class_name)
                field_name = field_name.strip()
                out.append(f"s.add(ReflectionAccessible(v('{class_name}', srt='class'), StringVal('{field_name}')))")
                return True
            else:
                out.append(f"# skipped malformed reflection_accessible: {r}")
                return False
                
        elif r.startswith("serializable("):
            class_name = r[13:-1].strip()
            class_name = sanitize_class_name(class_name)
            out.append(f"s.add(Serializable(v('{class_name}', srt='class')))")
            return True
            
        elif r.startswith("module_opens("):
            inner = r[13:-1]
            if "," in inner:
                module_name, package_name = [p.strip() for p in inner.split(",", 1)]
                module_name = sanitize_var_name(module_name)
                package_name = sanitize_var_name(package_name)
                out.append(f"s.add(ModuleOpens(v('{module_name}', srt='module'), v('{package_name}', srt='package')))")
                return True
            else:
                out.append(f"# skipped malformed module_opens: {r}")
                return False
                
        elif r.startswith("class_available("):
            class_name = r[16:-1].strip()
            class_name = sanitize_class_name(class_name)
            out.append(f"s.add(ClassAvailable(v('{class_name}', srt='class')))")
            return True
            
        elif r.startswith("cast_compatible("):
            # Sound cast modeling requires the actual subtype relation seeded
            # from the class hierarchy (closed-world, TPO-DP style). Until those
            # ground facts are wired in, treat cast_compatible as unsupported so
            # an undecided cast yields UNKNOWN rather than a free-variable sat.
            out.append(f"# unsupported cast compatibility (pending hierarchy facts): {r}")
            return False

        elif r.startswith("not_anonymous_class("):
            obj = r[len("not_anonymous_class("):-1].strip()
            if not obj:
                out.append(f"# skipped not_anonymous_class with empty operand: {r}")
                return False
            # An attacker can always supply a named (non-anonymous) class, so
            # this is satisfiable; assert it over the object's type name.
            out.append(f"s.add(NotAnonymous({_type_expr(obj)}))")
            return True
            
        else:
            out.append(f"# unknown runtime constraint: {r}")
            return False
            
    except Exception as e:
        out.append(f"# error processing runtime constraint {r}: {e}")
        return False

# ---------- CLI ----------
if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) < 2:
        print("Usage: python z3_translator_template.py <json_file>")
        sys.exit(1)
    
    with open(sys.argv[1], 'r') as f:
        data = json.load(f)
    
    script = generate_z3_script_from_json(data)
    print(script)
