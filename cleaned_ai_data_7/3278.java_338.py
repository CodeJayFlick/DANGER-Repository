class ProgramSymbolContextAction:
    def __init__(self, name: str, owner: str):
        pass  # equivalent to super().__init__()

    def is_enabled_for_context(self, action_context) -> bool:
        if not isinstance(action_context, ProgramSymbolActionContext):
            return False
        context = action_context
        if context.get_program() is None:
            return False
        return self.is_enabled_for_context(context)

    def perform_action(self, action_context: ActionContext):
        context = action_context  # equivalent to (ProgramSymbolActionContext) context
        self.action_performed(context)

    def is_valid_context(self, action_context: ActionContext) -> bool:
        if not isinstance(action_context, ProgramSymbolActionContext):
            return False
        return self.is_valid_context(action_context)

    def should_add_to_popup(self, action_context: ActionContext) -> bool:
        if not isinstance(action_context, ProgramSymbolActionContext):
            return False
        return self.should_add_to_popup(action_context)

    def should_add_to_popup_(self, context: ProgramSymbolActionContext) -> bool:
        return self.is_enabled_for_context(context)

    def is_valid_context_(self, context: ProgramSymbolActionContext) -> bool:
        return True

    def is_enabled_for_context_(self, context: ProgramSymbolActionContext) -> bool:
        return context.symbol_count != 0

    def action_performed(self, context: ProgramSymbolActionContext):
        pass  # abstract method
