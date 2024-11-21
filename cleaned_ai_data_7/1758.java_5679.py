class FunctionNameType:
    _values = [
        ("eFunctionNameTypeNone", None),
        ("eFunctionNameTypeAuto", "auto"),
        ("eFunctionNameTypeFull", "full"),
        ("eFunctionNameTypeBase", "base"),
        ("eFunctionNameTypeMethod", "method"),
        ("eFunctionNameTypeSelector", "selector"),
        ("eFunctionNameTypeAny", "any")
    ]

    def __init__(self, name):
        self.name = name
        FunctionNameType._next_value += 1

    @classmethod
    def swig_to_enum(cls, value):
        if not (0 <= value < len(cls._values)):
            raise ValueError(f"No enum {cls.__name__} with value {value}")
        return cls(*cls._values[value])

    @property
    def swig_value(self):
        return self._swig_value

    def __str__(self):
        return self.name


FunctionNameType._next_value = 0

e_function_name_type_none = FunctionNameType("eFunctionNameTypeNone")
e_function_name_type_auto = FunctionNameType("eFunctionNameTypeAuto")
e_function_name_type_full = FunctionNameType("eFunctionNameTypeFull")
e_function_name_type_base = FunctionNameType("eFunctionNameTypeBase")
e_function_name_type_method = FunctionNameType("eFunctionNameTypeMethod")
e_function_name_type_selector = FunctionNameType("eFunctionNameTypeSelector")
e_function_name_type_any = FunctionNameType("eFunctionNameTypeAny")

for attr, value in locals().items():
    if not (attr.startswith('e_') and isinstance(value, FunctionNameType)):
        continue
    globals()[f"swig_to_{attr}"] = lambda x: getattr(FunctionNameType.swig_to_enum(x), f"{attr}")
