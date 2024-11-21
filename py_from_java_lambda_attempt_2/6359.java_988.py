Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app.plugin.core.function import Function2Test
from ghidra_framework.plugintool import PluginTool
from ghidra_program.model.address import AddressFactory
from ghidra_program.model.listing import Program

class TestFunction2(unittest.TestCase):

    def setUp(self):
        self.env = None
        self.tool = None
        self.addr_factory = None
        self.program = None
        self.cb = None
        self.fp = None
        self.set_stack_depth_change_action = None
        self.remove_stack_depth_change_action = None

    def test_set_stack_depth_change_action(self):
        self.env.show_tool()
        load_program("notepad")
        id = -1
        try:
            program.start_transaction("Adding stack depth changes.")
            CallDepthChangeInfo.set_stack_depth_change(program, addr("01002493"), 16)
            CallDepthChangeInfo.set_stack_depth_change(program, addr("0100249b"), -10)
        finally:
            if id >= 0:
                program.end_transaction(id, True)

        self.cb.go_to_field(addr("0x1002493"), "Register Transition", 0, 0)
        self.assertEqual("StackDepth = StackDepth + 16", self.cb.get_current_field_text())
        self.cb.go_to_field(addr("0100249b"), "Register Transition", 0, 0)
        self.assertEqual("StackDepth = StackDepth - 10", self.cb.get_current_field_text())

    def test_set_stack_depth_change_action_at_call(self):
        self.env.show_tool()
        load_program("notepad")

        self.cb.go_to_field(addr("010022e6"), "Address", 0, 0)  # 10022e6 is Call to 1002cf5
        self.assertEqual(True, set_stack_depth_change_action.is_enabled_for_context(self.cb.get_provider().get_action_context(None)))

        check_function_purge("01002cf5", -20)

    def test_set_stack_depth_change_default_in_dialog(self):
        self.env.show_tool()
        load_program("notepad")

        self.cb.go_to_field(addr("010022e6"), "Address", 0, 0)  # 10022e6 is Call to 1002cf5
        self.assertEqual(True, set_stack_depth_change_action.is_enabled_for_context(self.cb.get_provider().get_action_context(None)))

    def test_remove_stack_depth_change_action(self):
        self.env.show_tool()
        load_program("notepad")
        id = -1
        try:
            program.start_transaction("Adding stack depth changes.")
            CallDepthChangeInfo.set_stack_depth_change(program, addr("01002493"), 16)
            CallDepthChangeInfo.set_stack_depth_change(program, addr("0100249b"), -10)
        finally:
            if id >= 0:
                program.end_transaction(id, True)

    def test_cancel_stack_depth_change_action_from_set_dialog(self):
        self.env.show_tool()
        load_program("notepad")

    def set_stack_depth_change(self, stack_depth_change_value):
        perform_action(set_stack_depth_change_action, self.cb.get_provider(), False)
        dialog = wait_for_stack_depth_change()
        text_field = get_text_field(dialog)
        trigger_text(text_field, stack_depth_change_value)
        press_buttonByText(dialog, "OK", True)

    def get_text_field(self, number_input_dialog):
        integer_text_field = getInstanceField("numberInputField", number_input_dialog)
        j_text_field = getInstanceField("textField", integer_text_field)
        return j_text_field

    def wait_for_stack_depth_change(self):
        dialog = waitForDialogComponent(tool.get_tool_frame(), NumberInputDialog.class, 2000)
        assertNotNull(dialog)
        component = findComponent(dialog, JTextField.class)
        assertNotNull(component)
        return dialog

    def check_function_purge(self, address_string, function_purge_value):
        addr = self.addr_factory.getAddress(address_string)
        f = program.getFunctionManager().getFunctionAt(addr)
        assertNotNull("Didn't find expected function at " + address_string, f)
        assertEquals("Unexpected function purge at " + address_string,
                      function_purge_value,
                      f.getStackPurgeSize())

    def wait_for_busy_tool(self):
        self.wait_for_busy_tool(tool)
        program.flushEvents()
        self.wait_for_swing()

def load_program(program_name):
    if "notepad".equals(program_name):
        classic_sample_x86_program_builder = ClassicSampleX86ProgramBuilder()
        program = builder.getProgram()

        pm = tool.getService(ProgramManager.class)
        pm.openProgram(program.getDomainFile())
        builder.dispose()
        wait_for_swing()
        addr_factory = program.getAddressFactory()
    else:
        assert fail("don't have program: " + program_name)

def getInstanceField(fieldName, obj):
    return getattr(obj, fieldName)

def findComponent(parent, clazz):
    for child in parent.getComponents():
        if isinstance(child, clazz):
            return child
    return None

def pressButtonByText(dialog, buttonText, cancel=False):
    button = findButtonByText(dialog, buttonText)
    if not cancel:
        button.doClick()
    else:
        button.cancel()

def triggerText(textField, textValue):
    textField.setText(textValue)

def getTextField(numberInputDialog):
    integer_text_field = getInstanceField("numberInputDialog", numberInputDialog)
    j_text_field = getInstanceField("textField", integer_text_field)
    return j_text_field

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The original code has many dependencies on specific classes and methods which are part of the Ghidra framework, so you would need to have those available in your Python environment for this code to work correctly.