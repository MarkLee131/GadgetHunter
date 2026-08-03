"""
json2z3.py
    usage:  python json2z3.py summary.json  > out.py
             python out.py
summary.json  is the LLM-emitted micro-IR ({vars, flow, guard})
"""
import json, sys
from textwrap import dedent

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
                else:
                    z[name] = Const(name, Obj)
            return z[name]
    """)

def emit_var_constraint(name, cons):
    if not isinstance(cons, str):
        return f"# unknown var-constraint (non-string): {cons}"
    if cons == "nonnull":
        return f"s.add(v('{name}') != NullO if v('{name}').sort()==Obj else v('{name}', srt='str') != NULL_S)"
    elif cons.startswith("=="):
        val = cons[2:].strip().strip('"')
        return f"s.add(v('{name}', srt='str') == StringVal('{val}'))"
    elif cons in ["StringSort", "Obj", "IntSort", "BoolSort"]:
        # Type declarations - handled in variable creation, no constraint needed
        return f"# {name} declared as {cons}"
    else:
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
    if not isinstance(j, dict):
        j = {"vars": [], "flow": [], "guard": [], "runtime": []}
    
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
            
            out.append(f"s.add(v('{src}') == v('{dst}'))")
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

    # Add enhanced solver check
    out += ["", "print('Enhanced Z3 Result:', s.check())", "if s.check()==sat:",
            "    m = s.model()", "    print('Logical Model:', m)",
            "    print('Runtime Feasibility: POTENTIALLY_FEASIBLE')",
            "    print('NOTE: Manual verification of runtime constraints recommended')",
            "else:", "    print('Runtime Feasibility: NOT_FEASIBLE')",
            "    print('Unsatisfiable core:', s.unsat_core())"]
    
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
            inner = g[4:-1]
            if "==" not in inner:
                out.append(f"# skipped malformed cmp guard: {g}")
                return False
            left, right = [p.strip() for p in inner.split('==', 1)]
            if not left:
                out.append(f"# skipped cmp guard with empty left side: {g}")
                return False
            left = sanitize_var_name(left)
            right = right.strip('"\'')  # Remove quotes
            out.append(f"s.add(v('{left}', srt='str') == StringVal('{right}'))")
            return True
            
        elif g.startswith("range("):
            inner = g[6:-1]
            parts = inner.split("<")
            if len(parts) != 3:
                out.append(f"# skipped malformed range guard: {g}")
                return False
            try:
                low, var, high = parts
                low_val = int(low.strip())
                high_val = int(high.strip())
                var = sanitize_var_name(var.strip())
                out.append(f"s.add(IntVal({low_val}) < v('{var}', srt='int'))")
                out.append(f"s.add(v('{var}', srt='int') < IntVal({high_val}))")
                return True
            except ValueError:
                out.append(f"# skipped range guard with non-integer bounds: {g}")
                return False
                
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
            inner = r[16:-1]
            if "," in inner:
                src_type, dst_type = [p.strip() for p in inner.split(",", 1)]
                src_type = sanitize_class_name(src_type)
                dst_type = sanitize_class_name(dst_type)
                out.append(f"# cast compatibility: {src_type} -> {dst_type}")
                return True
            else:
                out.append(f"# skipped malformed cast_compatible: {r}")
                return False
                
        elif r == "not_anonymous_class(obj)":
            out.append(f"# runtime constraint: obj must be named class")
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
