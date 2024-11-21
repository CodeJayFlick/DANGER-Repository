import unittest
from ghidra_app_plugin_core_function import ThunkReferenceAddressDialogTest


class TestThunkReferenceAddressDialog(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        builder = ClassicSampleX86ProgramBuilder()
        builder.create_external_function(None, "LibFoo", "xyz", "_Zxyz")
        program = builder.get_program()
        tool = env.launch_default_tool(program)
        code_browser_plugin = env.get_plugin(CodeBrowserPlugin())
        function_plugin = get_plugin(tool, FunctionPlugin())
        edit_thunk = get_action(function_plugin, "Set Thunked Function")
        revert_thunk = get_action(function_plugin, "Revert Thunk Function")

    def tearDown(self):
        self.env.dispose()

    @unittest.skip("This test is not implemented in Python yet.")
    def test_set_thunked_function(self):

        dialog = show_thunk_dialog(0x100194b)
        text_entry_field = find_component(dialog, JTextField())
        assert text_entry_field

        # Invalid Entry
        set_text(text_entry_field, "bar")
        press_button_by_text(dialog, "OK", False)

        error_dialog = wait_for_error_dialog()
        self.assertEqual("Invalid Entry Error", error_dialog.get_title())
        self.assertEqual(
            "Invalid thunk reference address or name specified: bar",
            error_dialog.get_message(),
        )
        press_button_by_text(error_dialog, "OK")

        # Try again
        set_text(text_entry_field, "IsTextUnicode")
        press_button_by_text(dialog, "OK")
        wait_for_busy_tool(tool)

        f = program.get_function_manager().get_function_at(0x100194b)
        self.assertTrue(f.is_thunk())
        thunked_function = f.get_thunked_function(False)
        assert thunked_function
        self.assertTrue(thunked_function.is_external())
        self.assertEqual("ADVAPI32.dll::IsTextUnicode", thunked_function.name(True))

    @unittest.skip("This test is not implemented in Python yet.")
    def test_set_thunked_function_with_namespace(self):

        dialog = show_thunk_dialog(0x100194b)
        text_entry_field = find_component(dialog, JTextField())
        assert text_entry_field

        set_text(text_entry_field, "ADVAPI32.dll::IsTextUnicode")
        press_button_by_text(dialog, "OK")
        wait_for_busy_tool(tool)

        f = program.get_function_manager().get_function_at(0x100194b)
        self.assertTrue(f.is_thunk())
        thunked_function = f.get_thunked_function(False)
        assert thunked_function
        self.assertTrue(thunked_function.is_external())
        self.assertEqual("ADVAPI32.dll::IsTextUnicode", thunked_function.name(True))

    @unittest.skip("This test is not implemented in Python yet.")
    def test_set_thunked_function_with_original_name(self):

        dialog = show_thunk_dialog(0x100194b)
        text_entry_field = find_component(dialog, JTextField())
        assert text_entry_field

        set_text(text_entry_field, "_Zxyz")
        press_button_by_text(dialog, "OK")

        wait_for_busy_tool(tool)

        f = program.get_function_manager().get_function_at(0x100194b)
        self.assertTrue(f.is_thunk())
        thunked_function = f.get_thunked_function(False)
        assert thunked_function
        self.assertTrue(thunked_function.is_external())
        self.assertEqual("LibFoo::xyz", thunked_function.name(True))

    @unittest.skip("This test is not implemented in Python yet.")
    def test_set_thunked_function_with_original_name_conflict(self):

        tx(program, lambda: program.get_symbol_table().create_label(0x1001900, "_Zxyz", SourceType.USER_DEFINED))
        dialog = show_thunk_dialog(0x100194b)
        text_entry_field = find_component(dialog, JTextField())
        assert text_entry_field
        set_text(text_entry_field, "_Zxyz")
        press_button_by_text(dialog, "OK", False)

        error_dialog = wait_for_error_dialog()
        self.assertEqual("Ambiguous Symbol Name", error_dialog.get_title())
        self.assertEqual(
            "Specified symbol is ambiguous.  Try full namespace name, mangled name or address.",
            error_dialog.get_message(),
        )
        press_button_by_text(error_dialog, "OK")
        wait_for_busy_tool(tool)

        f = program.get_function_manager().get_function_at(0x100194b)
        self.assertFalse(f.is_thunk())

        set_text(text_entry_field, "LibFoo::xyz")
        press_button_by_text(dialog, "OK", False)
        wait_for_busy_tool(tool)

        thunked_function = f.get_thunked_function(False)
        assert thunked_function
        self.assertTrue(thunked_function.is_external())
        self.assertEqual("LibFoo::xyz", thunked_function.name(True))

    def show_thunk_dialog(self, address):
        code_browser_plugin.go_to_field(address, FunctionSignatureFieldFactory.FIELD_NAME, 0, 0)
        wait_for_busy_tool(tool)

        action_context = code_browser_plugin.get_provider().get_action_context(None)

        self.assertTrue(edit_thunk.is_enabled_for_context(action_context))
        self.assertFalse(revert_thunk.is_enabled_for_context(action_context))

        perform_action(edit_thunk, action_context, False)

        dialog = wait_for_dialog_component(ThunkReferenceAddressDialog())
        return dialog

    def addr(self, offset):
        return program.get_address_factory().get_default_address_space().get_address(offset)


if __name__ == "__main__":
    unittest.main()
