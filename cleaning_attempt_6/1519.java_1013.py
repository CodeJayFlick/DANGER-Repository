class DebugModuleInfo:
    def __init__(self, event=None):
        self.event = event
        if event:
            self.num_modules = SBTarget.get_num_modules_from_event(event)
            for i in range(self.num_modules):
                module = SBTarget.get_module_at_index_from_event(i, event)
                self.modules[i] = module
        else:
            self.process = None
            self.event = None
            self.num_modules = 1
            self.modules[0] = None

    @property
    def number_of_modules(self):
        return self.num_modules

    def get_module(self, index):
        return self.modules[index]

    def __str__(self, index):
        module = self.get_module(index)
        if not isinstance(module, str):
            return f"{module}"
        else:
            return module

    @property
    def process(self):
        return SBProcess.get_process_from_event(self.event) if self.event else self.process


class SBTarget:
    @staticmethod
    def get_num_modules_from_event(event):
        pass  # implement this method in your Python code

    @staticmethod
    def get_module_at_index_from_event(index, event):
        pass  # implement this method in your Python code


class SBProcess:
    @staticmethod
    def get_process_from_event(event):
        pass  # implement this method in your Python code


# Usage example:

sb_target = SBTarget()
event = sb_target.get_num_modules_from_event()  # replace with actual implementation

debug_module_info = DebugModuleInfo(event)
print(debug_module_info.number_of_modules)  # prints the number of modules
