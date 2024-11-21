import ghidra.app.plugin.PluginCategoryNames
from ghidra.framework.model.DomainObject import DomainObject
from ghidra.program.model.address.AddressSet import AddressSet
from ghidra.program.model.listing.Listing import Listing
from ghidra.program.model.mem.MemoryBlock import MemoryBlock
from ghidra.util.Msg import Msg

class SampleProgramTreePlugin:
    def __init__(self, tool):
        super().__init__()
        self.create_actions()
        
    def create_actions(self):
        action = DockingAction("Create Sample Tree", "Sample Program Tree plugin")
        action.set_enabled_for_context(lambda context: self.current_program is not None)
        action.set_description("Plugin to create a program tree and modularize accordingly")

        tool.add_action(action)

    def modularize(self, current_program=None):
        cmd = ModularizeCommand()
        tool.execute_background_command(cmd, current_program)


class ModularizeCommand:
    def __init__(self):
        super().__init__()
        
    def apply_to(self, obj, monitor):
        program = DomainObject(obj)
        listing = program.get_listing()

        create_default_tree_view(program)

        memory = program.get_memory()
        root_module = listing.get_root_module("Sample Tree")

        address_set = AddressSet(memory)
        try:
            root_module.create_module("Fragments")
        except DuplicateNameException as e:
            pass

        fragments = listing.get_module("Sample Tree", "Fragments")
        
    def create_default_tree_view(self, program):
        tree_name = "Sample Tree"
        one_up = 1
        while listing.get_root_module(tree_name) is not None:
            tree_name += "_" + str(one_up)
            one_up += 1

        cmd = CreateDefaultTreeCmd(tree_name)
        if tool.execute(cmd, program):
            tool.set_status_info(cmd.status_msg)


class ProgramModule:
    def __init__(self, parent=None):
        self.parent = parent
        self.module_name = "Sample Module"
        
    def create_module(self, module_name):
        try:
            return self.parent.create_module(module_name)
        except DuplicateNameException as e:
            pass

    def get_module(self, tree_name, module_name):
        return listing.get_module(tree_name, module_name)


class ProgramFragment:
    def __init__(self, parent=None):
        self.parent = parent
        self.fragment_name = "Sample Fragment"
        
    def create_fragment(self, fragment_name):
        try:
            return self.parent.create_fragment(fragment_name)
        except DuplicateNameException as e:
            pass

    def move(self, start_address, end_address):
        try:
            frag.move(start_address, end_address)
        except NotFoundException as e:
            Msg.error(self,
                       "couln' t find addresses for fragment {} : {}".format(frag.fragment_name, start_address), e)


class CreateDefaultTreeCmd:
    def __init__(self, tree_name):
        self.tree_name = tree_name
        self.status_msg = None
        
    def execute(self, program=None):
        if tool.execute(self, program):
            return True
        else:
            return False

