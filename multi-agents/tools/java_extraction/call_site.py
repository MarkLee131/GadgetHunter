"""Recover the receiver expression of a call, for inter-gadget type threading.

Given a caller method's source and the name of the method the next gadget
dispatches, find that invocation and normalise its receiver to the constraint
vocabulary (`this`, `field.<name>`). Only high-confidence receiver forms are
returned; anything ambiguous yields None so the caller does not prune on a
guess (a wrong receiver would at worst map to a variable with no type
constraint, i.e. no effect).
"""

from typing import Optional

try:
    from tree_sitter import Language, Parser
    import tree_sitter_java as tsjava
    _PARSER = Parser(Language(tsjava.language()))
except Exception:  # tree-sitter optional; degrade to no recovery
    _PARSER = None


def recover_receiver(source_code: str, method_name: str) -> Optional[str]:
    """Return the receiver of the (first) call to `method_name` as `this` or
    `field.<name>`, or None if absent/ambiguous/unavailable."""
    if not _PARSER or not source_code or not method_name:
        return None
    try:
        tree = _PARSER.parse(bytes(source_code, "utf8"))
    except Exception:
        return None

    result = {"recv": None}

    def norm_object(obj) -> Optional[str]:
        if obj is None:
            return "this"                       # implicit this
        t = obj.type
        if t == "this":
            return "this"
        if t == "identifier":
            return "field." + obj.text.decode("utf8")   # best effort: bare field
        if t == "field_access":
            o = obj.child_by_field_name("object")
            f = obj.child_by_field_name("field")
            if f is not None and (o is None or o.type == "this"):
                return "field." + f.text.decode("utf8")
        return None

    def walk(node):
        if result["recv"] is not None:
            return
        if node.type == "method_invocation":
            name = node.child_by_field_name("name")
            if name is not None and name.text.decode("utf8") == method_name:
                recv = norm_object(node.child_by_field_name("object"))
                if recv is not None:
                    result["recv"] = recv
                    return
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return result["recv"]
