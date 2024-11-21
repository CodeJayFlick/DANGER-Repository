Here is the translation of the Java code to Python:
```
class DiffServiceProvider:
    def __init__(self, service_provider: object, program_diff_plugin: object):
        self.service_provider = service_provider
        self.program_diff_plugin = program_diff_plugin
        self.diff_program_manager = DiffProgramManager(self.program_diff_plugin)
        self.diff_goto_service = DiffGoToService(service_provider.get_service(GoToService), self.program_diff_plugin)

    def add_service_listener(self, listener: object):
        self.service_provider.add_service_listener(listener)

    def get_service(self, service_class: type) -> object:
        if service_class is ProgramManager:
            return self.diff_program_manager
        elif service_class is GoToService:
            return self.diff_goto_service
        else:
            return self.service_provider.get_service(service_class)

    def remove_service_listener(self, listener: object):
        self.service_provider.remove_service_listener(listener)
```
Note that I've used Python's type hinting system to indicate the types of variables and method parameters. This is not strictly necessary for a working translation, but it can help with code readability and maintainability.

Also, I've assumed that `DiffProgramManager` and `DiffGoToService` are classes defined elsewhere in your codebase. If they're not, you'll need to define them as well.