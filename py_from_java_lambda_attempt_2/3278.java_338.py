Here is the translation of the Java code to Python:
```
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
```
Note that I've used Python's type hinting system to indicate the expected types of variables and function parameters. This is not strictly necessary for a translation from Java to Python, but it can help with code readability and maintainability.

Also, I've kept the `action_performed` method as an abstract method in Python, since there is no direct equivalent to Java's abstract methods in Python. In a real-world implementation, you would need to provide a concrete implementation of this method in any subclass that inherits from `ProgramSymbolContextAction`.