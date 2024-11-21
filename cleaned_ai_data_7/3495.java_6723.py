class ClearPlugin:
    def __init__(self):
        self.clear_dialog = None
        self.clear_flow_dialog = None

    @staticmethod
    def clear_code_bytes_name():
        return "Clear Code Bytes"

    @staticmethod
    def clear_with_options_name():
        return "Clear With Options"

    @staticmethod
    def clear_flow_and_repair_name():
        return "Clear Flow and Repair"

    def create_actions(self):
        action_builder = ActionBuilder()
        action_builder.menu_path("Edit", self.clear_code_bytes_name())
        action_builder.popup_menu_path(self.clear_code_bytes_name())
        action_builder.on_action(lambda: self.clear_code_bytes())
        action_builder.build_and_install()

        action_builder = ActionBuilder()
        action_builder.menu_path("Edit", f"{self.clear_with_options_name()}...")
        action_builder.popup_menu_path(self.clear_with_options_name())
        action_builder.on_action(lambda: self.show_clear_all_dialog())
        action_builder.build_and_install()

        action_builder = ActionBuilder()
        action_builder.menu_path("Edit", self.clear_flow_and_repair_name() + "...")
        action_builder.popup_menu_path(self.clear_flow_and_repair_name())
        action_builder.on_action(lambda: self.show_clear_flow_dialog())
        action_builder.build_and_install()

    def is_clear_code_bytes_enabled(self):
        current_selection = context.get_selection()
        if current_selection and not current_selection.is_empty():
            return True
        elif (loc := context.get_location()) and loc.address:
            return True
        return False

    def clear_code_bytes(self, context):
        opts = ClearOptions()
        opts.set_clear_code(True)
        # ... set other options ...
        self.clear(opts, context)

    def show_clear_all_dialog(self, program_action_context):
        if not self.clear_dialog:
            self.clear_dialog = ClearDialog(self)
        self.clear_dialog.set_program_action_context(program_action_context)
        tool.show_dialog(self.clear_dialog)

    def show_clear_flow_dialog(self, context):
        if not self.clear_flow_dialog:
            self.clear_flow_dialog = ClearFlowDialog(self)
        self.clear_flow_dialog.set_program_action_context(context)
        tool.show_dialog(self.clear_flow_dialog)


class ActionBuilder:
    pass


class Tool:
    def execute_background_command(self, cmd, program):
        # ... implement this method ...


class ProgramActionContext:
    def get_selection(self):
        return None

    def get_location(self):
        return None

    def set_program_action_context(self, context):
        self.context = context


class ClearOptions:
    def __init__(self):
        self.clear_code = False
        # ... initialize other options ...

    def set_clear_code(self, value):
        self.clear_code = value

    # ... implement setter methods for other options ...
