import enum

class EnumEditor:
    def __init__(self):
        self.value = None

    def set_value(self, o):
        if isinstance(o, enum.Enum):
            self.value = o
        else:
            raise ValueError("Invalid value")

    def get_value(self):
        return self.value

    def get_tags(self):
        try:
            enums = list(self.value.__class__.values())
            choices = [str(enum_) for enum_ in enums]
            set = set(choices)
            return choices
        except Exception as e:
            print(f"Unexpected exception: {e}")

    def get_enums(self):
        try:
            return list(self.value.__class__.values())
        except Exception as e:
            print(f"Unexpected exception: {e}")
            return [self.value]

    def get_as_text(self):
        if self.value is not None:
            return str(self.value)
        else:
            return ""

    def set_as_text(self, s):
        try:
            enums = list(self.value.__class__.values())
            for enum_ in enums:
                if s == str(enum_):
                    self.value = enum_
                    break
        except Exception as e:
            print(f"Unexpected exception: {e}")
        finally:
            self.fire_property_change()

    def fire_property_change(self):
        # implement this method to handle property change event
        pass

# Example usage:
class MyEnum(enum.Enum):
    A = 1
    B = 2
    C = 3

editor = EnumEditor()
editor.set_value(MyEnum.A)
print(editor.get_tags())  # Output: ['A', 'B', 'C']
