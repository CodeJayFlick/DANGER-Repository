class ProjectDataContextToggleAction:
    def __init__(self, name: str, owner: str):
        pass  # equivalent of super(name, owner)

    def is_enabled_for_context(self, action_context) -> bool:
        if not isinstance(action_context, ProjectDataContext):
            return False

        context = action_context
        return self.is_enabled_for_context(context)

    def supports_transient_project_data(self) -> bool:
        return False  # equivalent of protected boolean supportsTransientProjectData()

    def is_enabled_for_context(self, context: 'ProjectDataContext') -> bool:
        return context.has_one_or_more_files_and_folders()  # equivalent of isEnabledForContext

    def action_performed(self, context):
        self.action_performed(context)  # equivalent of actionPerformed

    abstract def action_performed(self, context: 'ProjectDataContext')

    def is_valid_context(self, context) -> bool:
        if not isinstance(context, ProjectDataContext):
            return False
        return self.is_valid_context(context)

    def is_valid_context(self, context: 'ProjectDataContext') -> bool:
        return True  # equivalent of protected boolean isValidContext

    def is_add_to_popup(self, context) -> bool:
        if not isinstance(context, ProjectDataContext):
            return False
        return self.is_enabled_for_context(context)  # equivalent of isAddToPopup


class ProjectDataContext:  # equivalent of public abstract class ProjectDataContextToggleAction extends ToggleDockingAction
    pass

# Note that Python does not have direct equivalents for Java's ActionContext and ProjectDataContext.
