class ProgramContextAction:
    def __init__(self, name: str, owner: str):
        pass  # equivalent to super(name, owner)

    def is_enabled_for_context(self, action_context) -> bool:
        if not isinstance(action_context, ProgramActionContext):
            return False
        context = action_context
        if context.program is None:
            return False
        return self.is_enabled_for_context(context)

    def perform_action(self, context: ActionContext):
        program_context = context  # equivalent to (ProgramActionContext)context
        self.action_performed(program_context)

    def is_valid_context(self, context: ActionContext) -> bool:
        if not isinstance(context, ProgramActionContext):
            return False
        return self.is_valid_context(context)

    def should_add_to_popup(self, context: ActionContext) -> bool:
        if not isinstance(context, ProgramActionContext):
            return False
        return self.should_add_to_popup(context)

    def should_add_to_popup(self, program_action_context: ProgramActionContext) -> bool:
        return self.is_enabled_for_context(program_action_context)

    def is_valid_context(self, program_action_context: ProgramActionContext) -> bool:
        return True

    def is_enabled_for_context(self, program_action_context: ProgramActionContext) -> bool:
        return True

    def action_performed(self, program_context: ProgramActionContext):
        pass  # equivalent to abstract method in Java
