Here is the equivalent Python code:

```Python
import unittest
from collections import defaultdict

class ContextRegisterExtent:
    def __init__(self):
        self.context_registers = {}
        self.values_for_register = defaultdict(list)

    def add_context_info(self, info):
        for c in info:
            if c.register not in self.context_registers:
                self.context_registers[c.register] = True
            self.values_for_register[c.register].append(c.value)

    def get_values_for_register(self, register):
        return self.values_for_register[register]

    def __str__(self):
        return str(self.context_registers)


class TestContextRegisterExtent(unittest.TestCase):

    def test_empty_extent(self):
        cr_extent = ContextRegisterExtent()
        self.assertEqual({}, dict(cr_extent))
        self.assertTrue(not cr_extent.get_values_for_register("testRegister"))

    def test_null_inputs(self):
        cr_extent = ContextRegisterExtent()
        cr_extent.add_context_info(None)
        self.assertEqual({}, dict(cr_extent))

    def test_registers_and_values(self):
        one, two = 1, 2
        context_register1, context_register2 = "A", "B"
        cr_extent = ContextRegisterExtent()

        cinfo1 = {"register": context_register1, "value": one}
        cinfo2 = {"register": context_register1, "value": two}
        cinfo3 = {"register": context_register2, "value": one}

        info = [cinfo1, cinfo2, cinfo3]
        cr_extent.add_context_info(info)

        self.assertEqual(2, len(cr_extent.context_registers))
        self.assertIn(context_register1, cr_extent.context_registers)
        self.assertIn(context_register2, cr_extent.context_registers)

        values = cr_extent.get_values_for_register(context_register1)
        self.assertEqual([one, two], list(values))


if __name__ == "__main__":
    unittest.main()
```

Note: Python does not have direct equivalent of Java's `BigInteger` class. In this code, I used built-in integer type for simplicity. If you need to work with large integers, consider using the `gmpy2` library in Python.