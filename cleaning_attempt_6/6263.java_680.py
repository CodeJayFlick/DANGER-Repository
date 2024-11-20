import unittest
from ghidra.app.plugin.core.clipboard import ClipboardPlugin
from ghidra.framework.options import Options
from ghidra.program.database import ProgramBuilder
from ghidra.program.model.address import Address
from ghidra.program.model.data import DataType
from ghidra.program.model.listing import Listing

class CopyPasteFunctionInfoTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.tool_one = self.env.get_tool()
        setup_tool(self.tool_one)
        self.cb1 = get_plugin(self.tool_one, CodeBrowserPlugin)
        self.field_panel1 = cb1.get_field_panel()

        self.program_one = build_notepad("notepad")
        self.program_two = build_taskman("taskman")

    def tearDown(self):
        self.env.dispose()

    def test_paste_function_name(self):

        # in notepad (Browser(1)) copy ghidra function to taskman (Browser(2) at address 1004700
        symbol = get_unique_symbol(program_one, "ghidra")
        addr = symbol.get_address()
        go_to_addr(tool_one, addr)
        click1()

        tool_one.fire_plugin_event(ProgramSelectionPluginEvent("test", ProgramSelection(addr, addr), program_one))

        plugin = get_plugin(tool_one, ClipboardPlugin)
        service = getCode_browser_clipboard_content_provider_service(plugin)

        # paste at FUN_01004700 in taskman in Browser(2) (need a function that has the same offsets
        # in the stack in order for the names to be pasted).
        addr = get_addr(program_two, 0x1004700)
        go_to_addr(tool_two, addr)
        click2()

        paste(tool_two)

    def test_paste_function_comment(self):

        # create a function at entry
        func = get_function("ghidra")
        addr = func.get_entry_point()
        go_to_addr(tool_one, addr)
        click1()

        parameter_list = func.get_parameters()
        for var in parameter_list:
            if var.name == "param_7" or var.name == "param_9":
                tool_one.execute(SetVariableCommentCmd(var, "my stack comment for " + var.name), program_one)

    def test_paste_stack_variable_comment(self):

        # create a function at entry
        func = get_function("ghidra")
        addr = func.get_entry_point()
        go_to_addr(tool_one, addr)
        click1()

        parameter_list = func.get_parameters()
        for var in parameter_list:
            if var.name == "param_7" or var.name == "param_9":
                tool_one.execute(SetVariableCommentCmd(var, "my stack comment for " + var.name), program_one)

    def test_paste_stack_variable_name(self):

        # create a function at entry
        func = get_function("ghidra")
        addr = func.get_entry_point()
        go_to_addr(tool_one, addr)
        click1()

        parameter_list = func.get_parameters()
        for var in parameter_list:
            if var.name == "param_7" or var.name == "param_9":
                tool_one.execute(SetVariableNameCmd(var, "my_" + var.name), program_one)

    def test_paste_at_no_function(self):

        # pasting stack info where there is no function should do nothing; label and comments
        # should get pasted.
        func = get_function("ghidra")
        addr = func.get_entry_point()
        go_to_addr(tool_one, addr)
        click1()

    def paste(self, tool):
        plugin = get_plugin(tool, ClipboardPlugin)
        service = getCode_browser_clipboard_content_provider_service(plugin)

        # in Browser(2) go to a location where there is no function defined
        go_to_addr(tool_two, 0x0100176f)
        click2()

    def setup_tool(self, tool):
        tool.add_plugin(ClipboardPlugin)
        tool.add_plugin(CodeBrowserPlugin)
        tool.add_plugin(FunctionPlugin)

    def get_clipboard_action(self, plugin, service, action_name):
        map = getInstanceField("serviceActionMap", plugin)
        list = map.get(service)
        for plugin_action in list:
            if plugin_action.name == action_name:
                return plugin_action
        return None

    def go_to_addr(self, tool, addr):
        p = program_one
        if tool == tool_two:
            p = program_two
        tool.fire_plugin_event(ProgramLocationPluginEvent("test", AddressFieldLocation(p, addr), p))

    def get_addr(self, program, offset):
        return program.getMinAddress().getNewAddress(offset)

    def setup_notepad(self):

        # in notepad (Browser(1)) create a function at entry
        go_to_addr(tool_one, 0x01006420)
        action = get_action(get_plugin(tool_one, FunctionPlugin), "Create Function")
        perform_action(action, cb1.get_provider(), True)

    def reset_options(self):
        list_names = fieldOptions2.getOptionNames()
        for i in range(len(list_names)):
            name = list_names[i]
            if not name.startswith("Format Code"):
                continue
            if name.index("Show") >= 0 or name.index("Flag") >= 0:
                fieldOptions2.setBoolean(name, False)
            elif name.index("Lines") >= 0:
                fieldOptions2.setInt(name, 0)

    def getCode_browser_clipboard_content_provider_service(self, plugin):
        map = getInstanceField("serviceActionMap", plugin)
        set_key_set = map.keySet()
        for service in set_key_set:
            if service.getClass() == CodeBrowserClipboardProvider.class:
                return service
        return None

if __name__ == "__main__":
    unittest.main()

class TestEnv(unittest.TestCase):

    def get_tool(self):
        # code to create a tool goes here
        pass

def build_notepad(name):
    builder = ProgramBuilder(name, True, 0)
    builder.createMemory("test1", "0x01001000", 0x8000)
    builder.createEntryPoint("0x1006420", "entry")
    return builder.getProgram()

def get_unique_symbol(program, name):
    # code to create a unique symbol goes here
    pass

def click1():
    # code to simulate mouse click on field panel 1 goes here
    pass

def click2():
    # code to simulate mouse click on field panel 2 goes here
    pass

def get_plugin(tool, plugin_class):
    # code to create a plugin instance from the tool and class goes here
    pass

def perform_action(action, provider, enabled):
    # code to execute an action with a provider and enablement status goes here
    pass

def getInstanceField(fieldName, obj):
    # code to get an instance field value for a given object and name goes here
    pass

# other helper functions go here...
