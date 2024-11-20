Here is the equivalent Python code:

```Python
class RegisterKind:
    _values = [
        ("eRegisterKindEHFrame", 0),
        ("eRegisterKindDWARF", 1),
        ("eRegisterKindGeneric", 2),
        ("eRegisterKindProcessPlugin", 3),
        ("eRegisterKindLLDB", 4),
        ("kNumRegisterKinds", 5)
    ]

    def __init__(self, name):
        self.name = name
        RegisterKind._next_value += 1

    @classmethod
    def swig_to_enum(cls, value):
        if not (0 <= value < len(RegisterKind._values)):
            raise ValueError(f"No enum {cls.__name__} with value {value}")
        return cls(*RegisterKind._values[value])

    @property
    def name(self):
        return self.name

    @property
    def value(self):
        return RegisterKind._next_value - 1

    _next_value = 0

    e_register_kind_eh_frame = None
    e_register_kind_dwarf = None
    e_register_kind_generic = None
    e_register_kind_process_plugin = None
    e_register_kind_lldb = None
    k_num_register_kinds = None

    def __init__():
        RegisterKind.e_register_kind_eh_frame = RegisterKind("eRegisterKindEHFrame")
        RegisterKind.e_register_kind_dwarf = RegisterKind("eRegisterKindDWARF")
        RegisterKind.e_register_kind_generic = RegisterKind("eRegisterKindGeneric")
        RegisterKind.e_register_kind_process_plugin = RegisterKind("eRegisterKindProcessPlugin")
        RegisterKind.e_register_kind_lldb = RegisterKind("eRegisterKindLLDB")
        RegisterKind.k_num_register_kinds = RegisterKind("kNumRegisterKinds")

    def __str__(self):
        return self.name

# Initialize the values
__init__()
```

Please note that Python does not have a direct equivalent to Java's `public` and `private` access modifiers. The `_values`, `_next_value`, etc., are intended as internal variables, but they can still be accessed from outside the class if you want them to.