class ProgramTreeAction:
    SINGLE_SELECTION = 0
    MULTI_SELECTION = 1

    def __init__(self, name: str, owner: str, default_popup_path=None, key_binding=None):
        self.selection_type = self.MULTI_SELECTION if key_binding is None else self.SINGLE_SELECTION
        super().__init__(name, owner)
        
        if key_binding:
            self.set_key_binding(key_binding)

    def set_key_binding(self, key_binding):
        # Assuming you have a KeyBindingData class in Python
        self.key_binding_data = KeyBindingData(key_binding)

    @property
    def selection_type(self) -> int:
        return self._selection_type

    @selection_type.setter
    def selection_type(self, value: int):
        if not isinstance(value, int):
            raise TypeError("Selection type must be an integer")
        self._selection_type = value

    def is_valid_context(self, context):
        try:
            program_node = context.get_context_object()
            return isinstance(program_node, ProgramNode)
        except AttributeError as e:
            print(f"Error: {e}")
            return False

    def is_add_to_popup(self, context):
        return True

class KeyBindingData:
    # Assuming you have a class for key binding data in Python
    pass

class ProgramNode:
    # Assuming you have a class for program nodes in Python
    pass
