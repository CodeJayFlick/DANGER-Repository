class KeyBindingData:
    def __init__(self, key_stroke):
        self.key_stroke = key_stroke
        self.key_binding_precedence = "DefaultLevel"

    @classmethod
    def from_char(cls, c, modifiers):
        return cls((ord(c.upper()), modifiers))

    @classmethod
    def from_key_code_and_modifiers(cls, keyCode, modifiers):
        return cls(KeyStroke(keyCode, modifiers))

    @classmethod
    def from_string(cls, key_stroke_string):
        try:
            return cls(parse_key_stroke_string(key_stroke_string))
        except ValueError as e:
            raise ValueError(f"Invalid keystroke string: {key_stroke_string}") from e

    @staticmethod
    def parse_key_stroke_string(key_stroke_string):
        try:
            key_stroke = KeyBindingUtils.parse_key_stroke(key_stroke_string)
            if key_stroke is None:
                raise ValueError("Invalid keystroke string")
            return key_stroke
        except Exception as e:
            raise ValueError(f"Failed to parse keystroke: {key_stroke_string}") from e

    def __init__(self, key_stroke, precedence):
        if precedence == "ReservedActionsLevel":
            raise ValueError("Can't set precedence to Reserved")
        self.key_stroke = key_stroke
        self.key_binding_precedence = precedence

    @property
    def get_key_binding(self):
        return self.key_stroke

    @property
    def get_key_binding_precedence(self):
        return self.key_binding_precedence

    def __str__(self):
        return f"{type(self).__name__}[KeyStroke={self.key_stroke}, precedence={self.key_binding_precedence}]"

    @classmethod
    def create_reserved_key_binding_data(cls, key_stroke):
        data = KeyBindingData(key_stroke)
        data.key_binding_precedence = "ReservedActionsLevel"
        return data

    @staticmethod
    def validate_key_binding_data(new_key_binding_data):
        if new_key_binding_data is None:
            return None

        binding = new_key_binding_data.get_key_binding()
        if binding is None:
            # not sure when this can happen
            return new_key_binding_data

        precedence = new_key_binding_data.get_key_binding_precedence()
        if precedence == "ReservedActionsLevel":
            return KeyBindingData.create_reserved_key_binding_data(binding)
        else:
            return KeyBindingData(binding, precedence)

class KeyStroke:
    def __init__(self, keyCode, modifiers):
        self.keyCode = keyCode
        self.modifiers = modifiers

def parse_key_stroke_string(key_stroke_string):
    # implement this method to handle parsing of key stroke string
    pass

class KeyBindingUtils:
    @staticmethod
    def parse_key_stroke(key_stroke_string):
        # implement this method to handle parsing of keystroke string
        pass

    @classmethod
    def validate_keyStroke(cls, key_binding):
        return key_binding
