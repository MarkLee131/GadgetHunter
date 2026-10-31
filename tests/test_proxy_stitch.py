import json
import tempfile
import unittest
from pathlib import Path

from scan_rules.proxy_stitch import stitch


def edge(kind, caller, contr, callee):
    return f"[{kind}] <{caller}> --(line:7, constraint:[{contr}])--> <{callee}>"


class ProxyStitchTests(unittest.TestCase):
    def _scan(self, chains, roots):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name)
        (folder / "manifest.json").write_text(json.dumps({"proxy_roots": roots}))
        (folder / "chains").write_text("\n\n".join(chains))
        return folder

    def test_stitches_controllable_reflective_prefix_to_handler_fragment(self):
        handler = "com.h.H: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
        prefix = "\n".join([
            edge("VIRTUAL", "a.Entry: void readObject(java.io.ObjectInputStream)", "-1", "a.Gadget: java.lang.Object morph(java.lang.Object)"),
            # Reflective facade on a controllable bean (constraint[0] = -1): a proxy injection point.
            edge("STATIC", "a.Gadget: java.lang.Object morph(java.lang.Object)", "-1, 0", "org.apache.commons.beanutils.PropertyUtils: java.lang.Object getProperty(java.lang.Object,java.lang.String)"),
        ])
        fragment = "\n".join([
            edge("INTERFACE", handler, "-1", "b.Mid: java.lang.Object run()"),
            edge("VIRTUAL", "b.Mid: java.lang.Object run()", "-1", "java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])"),
        ])
        leads, prefixes, fragments = stitch(self._scan([prefix, fragment], [f"<{handler}>"]))
        self.assertEqual(fragments, 1)
        self.assertTrue(leads)
        top = leads[0]
        self.assertEqual(top["handler"], handler)
        self.assertEqual(top["priority"], 3)
        self.assertIn("a.Gadget.morph", top["prefix_gadgets"])

    def test_not_controllable_receiver_is_not_a_stitch_point(self):
        handler = "com.h.H: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
        # constraint[0] = -3 (not polluted): the receiver is not attacker-controllable.
        prefix = "\n".join([
            edge("VIRTUAL", "a.Entry: void readObject(java.io.ObjectInputStream)", "-1", "a.Gadget: java.lang.Object morph(java.lang.Object)"),
            edge("STATIC", "a.Gadget: java.lang.Object morph(java.lang.Object)", "-3, 0", "org.apache.commons.beanutils.PropertyUtils: java.lang.Object getProperty(java.lang.Object,java.lang.String)"),
        ])
        fragment = edge("VIRTUAL", handler, "-1", "java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])")
        leads, prefixes, fragments = stitch(self._scan([prefix, fragment], [f"<{handler}>"]))
        self.assertEqual(leads, [])

    def test_requires_proxy_roots(self):
        with self.assertRaises(ValueError):
            stitch(self._scan(["[VIRTUAL] <a.B: void c()> --(line:1, constraint:[-1])--> <d.E: void f()>"], []))


if __name__ == "__main__":
    unittest.main()
