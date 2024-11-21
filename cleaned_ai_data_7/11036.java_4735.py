class ProjectTreeAction:
    def __init__(self, name: str, owner: str):
        pass  # No direct equivalent in Python for super() call.

    def is_enabled_for_context(self, action_context) -> bool:
        if not isinstance(action_context, FrontEndProjectTreeContext):
            return False
        context = action_context
        return self.is_enabled_for_context(context)

    @property
    def supports_transient_project_data(self) -> bool:
        return False

    def is_enabled_for_context(self, context: FrontEndProjectTreeContext) -> bool:
        return context.has_one_or_more_files_and_folders()

    def perform_action(self, action_context):
        if not isinstance(action_context, FrontEndProjectTreeContext):
            raise TypeError("Invalid Action Context")
        self._perform_action(action_context)

    @abstractmethod
    def _perform_action(self, front_end_project_tree_context: FrontEndProjectTreeContext) -> None:
        pass

    def is_valid_context(self, action_context) -> bool:
        if not isinstance(action_context, FrontEndProjectTreeContext):
            return False
        context = action_context
        return self.is_valid_context(context)

    @property
    def supports_transient_project_data(self) -> bool:
        return True  # No direct equivalent in Python for this method.

    def is_add_to_popup(self, action_context: ActionContext) -> bool:
        if not isinstance(action_context, FrontEndProjectTreeContext):
            raise TypeError("Invalid Action Context")
        context = action_context
        return self.is_enabled_for_context(context)

class FrontEndProjectTreeContext:
    pass

# You need to define this class in Python as well.
