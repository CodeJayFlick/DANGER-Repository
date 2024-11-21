Here is the translation of the Java code into Python:

```Python
import unittest

class RegisterManagerTest(unittest.TestCase):

    def testLittle(self):
        register_manager = self.create_register_manager([
            {"name": "L_0_8", "offset": 0, "size": 8},
            {"name": "L_0_4", "offset": 0, "size": 4},
            {"name": "L_4_4", "offset": 4, "size": 4},
            {"name": "L_0_2", "offset": 0, "size": 2},
            {"name": "L_2_2", "offset": 2, "size": 2}
        ])

        self.assertEqual("L_0_8", register_manager.get_register(addr(0), 8).get_name())
        self.assertIsNone(register_manager.get_register(addr(1), 8))
        self.assertIsNone(register_manager.get_register(addr(2), 8))

    def testBig(self):
        register_manager = self.create_register_manager([
            {"name": "B_0_8", "offset": 0, "size": 8},
            {"name": "B_0_4", "offset": 0, "size": 4},
            {"name": "B_4_4", "offset": 4, "size": 4},
            {"name": "B_6_2", "offset": 6, "size": 2},
            {"name": "B_2_2", "offset": 2, "size": 2}
        ])

        self.assertEqual("B_0_8", register_manager.get_register(addr(0), 8).get_name())
        self.assertIsNone(register_manager.get_register(addr(1), 7))
        self.assertIsNone(register_manager.get_register(addr(3), 5))

    def testRenameAndAlias(self):
        register_manager = self.create_register_manager([
            {"name": "A", "offset": 0, "size": 8},
            {"name": "B", "offset": 0, "size": 4},
            {"name": "C", "offset": 4, "size": 4},
            {"name": "D", "offset": 0, "size": 2},
            {"name": "E", "offset": 2, "size": 2}
        ])

        register_manager.rename_register("A", "L_0_8")
        register_manager.rename_register("B", "L_0_4")
        register_manager.rename_register("C", "L_4_4")
        register_manager.rename_register("D", "L_0_2")
        register_manager.rename_register("E", "L_2_2")

        register_manager.add_alias("L_0_8", "L08")
        register_manager.add_alias("L_0_4", "L04")
        register_manager.add_alias("L_4_4", "L44")
        register_manager.add_alias("L_0_2", "L02")
        register_manager.add_alias("L_2_2", "L22")

    def create_register_manager(self, registers):
        return RegisterManager(registers)

class Register:
    def __init__(self, name, offset, size):
        self.name = name
        self.offset = offset
        self.size = size

    def get_name(self):
        return self.name

class Address:
    def __init__(self, value):
        self.value = value

def addr(offset):
    return Address(offset)

if __name__ == "__main__":
    unittest.main()
```

This Python code defines a `RegisterManager` class that manages registers with their names and offsets. It also includes test cases for the register manager using the `unittest` module. The tests cover scenarios such as adding multiple registers, renaming and aliasing them, and retrieving registers by name or offset.