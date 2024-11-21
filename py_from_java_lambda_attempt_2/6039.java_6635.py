Here is the translation of the given Java code into Python:

```Python
import unittest

class StorageEditorModelTest(unittest.TestCase):

    def setUp(self):
        self.program = ProgramBuilder("TestProgram", "EAX")
        self.builder = program.createMemory("block1", "1000", 1000)
        self.fun = builder.createEmptyFunction("bob", "1000", 20, VoidDataType())
        self.stack_space = program.getAddressFactory().getStackSpace()
        create_storage_model(8, 4, False)

    def test_size_check(self):
        self.assertEqual(model.get_current_size(), 4)
        self.assertTrue(model.is_valid())
        self.assertEqual("Warning: Not enough storage space allocated", model.get_status_text())

        model.set_varnode(varnodes[0], varnodes[0].get_address(), 12)
        self.assertTrue(model.is_valid())
        self.assertEqual("Warning: Too much storage space allocated", model.get_status_text())

        model.set_varnode(varnodes[0], varnodes[0].get_address(), REQUIRE_SIZE)
        self.assertTrue(model.is_valid())
        self.assertEqual("", model.get_status_text())

    def test_add_storage(self):
        self.assertEqual(len(model.get_varnodes()), 1)

        data_change_called = False
        model.add_varnode()
        while not data_change_called:
            pass

        self.assertTrue(data_change_called)
        self.assertEqual(2, len(model.get_varnodes()))
        varnodes = model.get_varnodes()
        varnode_info = varnodes[1]
        self.assertEqual(VarnodeType.Register, varnode_info.get_type())
        self.assertIsNone(varnode_info.get_address())

    def test_remove(self):
        model.set_selected_varnoderows([0])
        self.assertTrue(model.can_remove_varnodes())

        model.add_varnode()
        self.assertEqual(2, len(model.get_varnodes()))
        self.assertTrue(model.can_remove_varnodes())

        data_change_called = False
        model.remove_varnodes()
        while not data_change_called:
            pass

        self.assertTrue(data_change_called)
        varnodes = model.get_varnodes()
        self.assertEqual(1, len(varnodes))
        varnode_info = varnodes[0]
        self.assertEqual(VarnodeType.Register, varnode_info.get_type())

    def test_remove_all(self):
        model.add_varnode()
        self.assertTrue(model.can_remove_varnodes())
        model.set_selected_varnoderows([0, 1])
        self.assertTrue(model.can_remove_varnodes())
        model.remove_varnodes()

        while not data_change_called:
            pass

        self.assertTrue(data_change_called)
        varnodes = model.get_varnodes()
        self.assertEqual(0, len(varnodes))

    def test_move_up_down_enablement(self):
        # no selection, both buttons disabled
        model.set_selected_varnoderows([])
        self.assertFalse(model.can_move_varnode_up())
        self.assertFalse(model.can_move_varnode_down())

        # multiple selection, both buttons disabled
        model.set_selected_varnoderows([0, 1])
        self.assertFalse(model.can_move_varnode_up())
        self.assertFalse(model.can_move_varnode_down())

    def test_move_up(self):
        varnodes = model.get_varnodes()
        self.assertEqual(2, len(varnodes))
        self.assertEqual(VarnodeType.Stack, varnodes[0].get_type())
        self.assertEqual(VarnodeType.Register, varnodes[1].get_type())

        # select the last row
        model.set_selected_varnoderows([1])

        model.move_selected_varnode_up()

    def test_move_down(self):
        varnodes = model.get_varnodes()
        self.assertEqual(2, len(varnodes))
        self.assertEqual(VarnodeType.Stack, varnodes[0].get_type())
        self.assertEqual(VarnodeType.Register, varnodes[1].get_type())

        # select the first row
        model.set_selected_varnoderows([0])

        model.move_selected_varnode_down()

    def test_changing_type_clears_address_but_keeps_size(self):
        varnode = model.get_varnodes()[0]
        self.assertTrue(model.is_valid())
        self.assertEqual(VarnodeType.Stack, varnode.get_type())
        self.assertIsNotNone(varnode.get_address())

        model.set_varnodedtype(varnode, VarnodeType.Register)
        self.assertIsNone(varnode.get_address())
        self.assertEqual(8, varnode.get_size().value)

    def test_duplicate_storage_address(self):
        varnode = model.get_varnodes()[0]
        model.set_varnodetype(varnode, VarnodeType.Register)
        model.set_varnodedaddress(program.get_register(test_reg_name).get_address(), 4)

        model.add_varnode()
        varnode_info = model.get_varnodes()[1]
        model.set_varnodedaddress(program.get_register(test_reg_name).get_address(), 2)
        self.assertFalse(model.is_valid())
        self.assertEqual("Row 1: Overlapping storage address used.", model.get_status_text())

if __name__ == '__main__':
    unittest.main()
```

Please note that this is a direct translation of the given Java code into Python.