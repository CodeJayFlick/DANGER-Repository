class DomainFileProviderContextAction:
    def __init__(self, name: str, owner: str):
        pass  # equivalent of super(name, owner)

    def is_enabled_for_context(self, action_context) -> bool:
        if not isinstance(action_context, DomainFileContext):  # equivalent of instanceOf
            return False

        front_end_tool = AppInfo.get_front_end_tool()  # assuming this method exists in the same class or another one with similar functionality
        if front_end_tool.is_executing_command():
            return False

        return self._is_enabled_for_context(action_context)

    def _is_enabled_for_context(self, context: DomainFileContext) -> bool:
        return context.get_file_count() > 0


    def action_performed(self, context):
        if not isinstance(context, DomainFileContext):  # equivalent of instanceOf
            raise ValueError("Invalid Context")
        self._action_performed(context)

    def _action_performed(self, context: DomainFileContext) -> None:
        pass  # abstract method in Python


    def is_valid_context(self, action_context) -> bool:
        if not isinstance(action_context, DomainFileContext):  # equivalent of instanceOf
            return False

        return self._is_valid_context(action_context)

    def _is_valid_context(self, context: DomainFileContext) -> bool:
        return True


    def is_add_to_popup(self, action_context) -> bool:
        if not isinstance(action_context, DomainFileContext):  # equivalent of instanceOf
            return False

        front_end_tool = AppInfo.get_front_end_tool()  # assuming this method exists in the same class or another one with similar functionality
        if front_end_tool.is_executing_command():
            return False

        return self._is_add_to_popup(action_context)

    def _is_add_to_popup(self, context: DomainFileContext) -> bool:
        return self._is_enabled_for_context(context)
