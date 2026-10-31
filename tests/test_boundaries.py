"""Derived secondary-deserialization boundaries (no backend)."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scan_rules.boundaries import derive_stream_boundaries, stream_parameters
from scan_rules.inventory import Code, Method, inventory

ROOT = Path(__file__).resolve().parents[1]
OIS = ("java.io.ObjectInputStream", "<init>", "(Ljava/io/InputStream;)V")
BAIS = ("java.io.ByteArrayInputStream", "<init>", "([B)V")


def method(body, refs, parameters=("java.io.InputStream",), static=True):
    return Method("p.H", "read", "java.lang.Object", parameters, 0x0009 if static else 0x0001,
                  Code(bytes(body), 4, 0, refs, {}))


class BoundaryTests(unittest.TestCase):
    def test_direct_and_wrapped_parameters(self):
        # new OIS; dup; aload_0; invokespecial OIS.<init>; areturn
        direct = method([0xbb, 0, 9, 0x59, 0x2a, 0xb7, 0, 1, 0xb0], {1: OIS})
        self.assertEqual(stream_parameters(direct), {0})
        # new OIS; dup; new BAIS; dup; aload_0; BAIS.<init>; OIS.<init>; areturn
        wrapped = method([0xbb, 0, 9, 0x59, 0xbb, 0, 8, 0x59, 0x2a, 0xb7, 0, 2, 0xb7, 0, 1, 0xb0], {1: OIS, 2: BAIS}, ("byte[]",))
        self.assertEqual(stream_parameters(wrapped), {0})
        # Instance method: slot 1 is the first parameter.
        instance = method([0xbb, 0, 9, 0x59, 0x2b, 0xb7, 0, 1, 0xb0], {1: OIS}, static=False)
        self.assertEqual(stream_parameters(instance), {0})

    def test_reassigned_or_unrelated_inputs_are_not_boundaries(self):
        # astore_0 before use: the slot no longer holds the caller's argument.
        reassigned = method([0x01, 0x4b, 0xbb, 0, 9, 0x59, 0x2a, 0xb7, 0, 1, 0xb0], {1: OIS})
        self.assertEqual(stream_parameters(reassigned), set())
        # A field or constant stream is not a parameter.
        field = method([0xbb, 0, 9, 0x59, 0x01, 0xb7, 0, 1, 0xb0], {1: OIS})
        self.assertEqual(stream_parameters(field), set())

    @unittest.skipUnless(shutil.which("javac"), "javac required")
    def test_fixture_wrappers(self):
        with tempfile.TemporaryDirectory() as folder:
            subprocess.run(["javac", "--release", "8", "-d", folder, str(ROOT / "tests/fixtures/taint/Wrappers.java")],
                           check=True, capture_output=True)
            rules = derive_stream_boundaries(inventory([Path(folder)], include_code=True), set())
        names = {rule["method"].split(" ")[-1].split("(")[0] for rule in rules}
        self.assertEqual(names, {"stream", "bytes", "read"})  # 'unrelated' reads new byte[0]


if __name__ == "__main__":
    unittest.main()
