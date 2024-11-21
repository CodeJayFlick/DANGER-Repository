Here is the translation of the Java code into Python:

```Python
class ModuleAlgorithmPlugin:
    def __init__(self):
        pass  # Initialize plugin here if needed

    def init(self):
        self.block_model_service = None
        self.actions = []

    def dispose(self):
        if self.block_model_service is not None:
            self.block_model_service.remove_listener(self)
            self.block_model_service = None

    def update_subroutine_actions(self, tool=None):
        # Remove old actions
        for action in self.actions:
            tool.remove_action(action)

        help_location = "ProgramTreePlugin", "Modularize_By_Subroutine"

        sub_models = self.block_model_service.get_available_model_names(BlockModelService.SUBROUTINE_MODEL)
        if len(sub_models) > 1:  # Not needed if only one subroutine model
            self.actions = [DockingAction(f"Modularize By Subroutine [{model_name}]", "Module Algorithm Plugin") for model_name in sub_models]
            for i, action in enumerate(self.actions):
                action.set_popup_menu_data({"Menu": f"Modularize By", "Subroutine": sub_models[i]})
                tool.add_action(action)
        else:
            self.actions = [DockingAction("Modularize By Subroutine", "Module Algorithm Plugin")]
            self.actions[0].set_popup_menu_data({"Menu": ["Modularize By"], "Subroutine": None})
            tool.add_action(self.actions[0])

    def apply_module_algorithm(self, model_name=None, active_object=None):
        if isinstance(active_object, ProgramNode):
            cmd = ModuleAlgorithmCmd(active_object.get_group_path(), active_object.get_group().get_tree_name(),
                                      self.block_model_service, model_name)
            tool.execute_background_command(cmd)

    def program_deactivated(self, program):
        for action in self.actions:
            action.set_enabled(False)

    def program_activated(self, program):
        for action in self.actions:
            action.set_enabled(True)

    def model_added(self, mode_name=None, model_type=BlockModelService.SUBROUTINE_MODEL):
        if model_type == BlockModelService.SUBROUTINE_MODEL:
            self.update_subroutine_actions()

    def model_removed(self, mode_name=None, model_type=BlockModelService.SUBROUTINE_MODEL):
        if model_type == BlockModelService.SUBROUTINE_MODEL:
            self.update_subroutine_actions()
```

Note that this is a direct translation of the Java code into Python. Some changes were made to adapt it to Python's syntax and semantics:

- The `@PluginInfo` annotation was removed, as there is no equivalent in Python.
- The `createTreeAction` variable was not translated, as its purpose seems unclear from the provided information.
- The `currentProgram` variable was also not translated, as its scope and usage are unknown.