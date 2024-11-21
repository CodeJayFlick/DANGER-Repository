class ReservedKeyBindingAction:
    def __init__(self, tool: object, action: object, key_stroke):
        super().__init__(tool, action, key_stroke)

    @property
    def reserved_keybinding_precedence(self) -> bool:
        return True

    @property
    def get_key_binding_precedence(self) -> str:
        from enum import Enum
        class KeyBindingPrecedence(Enum):
            ReservedActionsLevel = "ReservedActionsLevel"
        
        return KeyBindingPrecedence.ReservedActionsLevel.name
