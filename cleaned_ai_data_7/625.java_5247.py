import collections
from ghidra.util import msg

class DbgListModulesCommand:
    def __init__(self, manager, process):
        self.manager = manager
        self.process = process
        self.updated_modules = {}
        self.module_info = {}

    def complete(self, pending):
        modules = self.process.get_known_modules()
        for id in self.updated_modules.keys():
            if id in modules:
                continue  # Do nothing, we're in sync
            msg.warn(self, f"Resync: Was missing module {id}")
            info = self.module_info[id]
            module = DbgModuleImpl(manager, process, info)
            module.add()
        for id in list(modules.keys()):
            if id not in self.updated_modules:
                self.process.remove_module(id)
        return self.process.get_known_modules()

    def invoke(self):
        system_objects = self.manager.get_system_objects()
        system_objects.set_current_process_id(self.process.id)
        symbols = self.manager.get_symbols()
        for module in symbols.iterate_modules(0):
            info = symbols.get_module_parameters(1, module.index)
            image_name = module.name(DebugModuleName.IMAGE)
            module_name = module.name(DebugModuleName.MODULE)
            info.image_name = image_name
            info.module_name = module_name
            self.updated_modules[info.to_string()] = module
            self.module_info[module] = info

class DbgModuleImpl:
    def __init__(self, manager, process, info):
        self.manager = manager
        self.process = process
        self.info = info

    def add(self):
        pass  # Not implemented in the original Java code

# Note: The above Python code assumes that `DbgProcess`, `DebugModuleInfo`, and other classes are defined elsewhere.
