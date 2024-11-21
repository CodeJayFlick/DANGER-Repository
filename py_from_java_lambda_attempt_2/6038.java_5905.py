Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.program.database import ProgramBuilder
from ghidra.util.exception import InvalidInputException

class StorageEditorModelBETest(unittest.TestCase):

    def __init__(self):
        super().__init__()
        self.model = None
        self.program = None

    def setUp(self):
        self.program = ProgramBuilder._SPARC64("g0")
        self.model = program.getStorageEditorModel()

    @unittest.skipIf(not hasattr(model, 'getVarnodes'), "This test requires a valid model with varnodes.")
    def testDuplicateStorageAddress(self):
        varnode_info = list(self.model.getVarnodes())[0]
        self.model.set_varnode_type(varnode_info, VarnodeType.Register)
        self.model.set_varnode(varnode_info, program.getRegister("g1").get_address().add(4), 4)

        self.model.add_varnode()
        varnode_info = list(self.model.getVarnodes())[1]
        self.model.set_varnode(varnode_info, program.getRegister("g1").get_address().add(6), 2)
        self.assertTrue(not self.model.is_valid())
        self.assertEqual("Row 1: Overlapping storage address used.", self.model.get_status_text())

    @unittest.skipIf(not hasattr(program, 'get_register'), "This test requires a valid program with register.")
    def test_Changing_Size_Affects_Address(self):
        try:
            register = self.program.getRegister("g1")
            assert register is not None

            # Test constrained
            create_storage_model(4, 4, False)
            varnode_info = list(self.model.getVarnodes())[0]
            self.model.set_varnode_type(varnode_info, VarnodeType.Register)
            self.assertEqual(4, varnode_info.size())
            self.assertEqual(64, register.bit_length)
            self.model.set_varnode(varnode_info, register)
            self.assertEqual(register.address.offset + 4,
                              varnode_info.address.offset)
            self.assertEqual(4, varnode_info.size())

            # Test unconstrained
            create_storage_model(4, 4, True)
            varnode_info = list(self.model.getVarnodes())[0]
            self.model.set_varnode_type(varnode_info, VarnodeType.Register)
            self.assertEqual(4, varnode_info.size())
            self.assertEqual(64, register.bit_length)
            self.model.set_varnode(varnode_info, register)
            self.assertEqual(register.address.offset,
                              varnode_info.address.offset)
            self.assertEqual(8, varnode_info.size())

        except InvalidInputException as e:
            print(f"Invalid input exception: {e}")

if __name__ == '__main__':
    unittest.main()
```

Please note that the above Python code is not a direct translation of Java to Python. It's more like an adaptation of the given Java code into Python, considering the differences between these two languages.