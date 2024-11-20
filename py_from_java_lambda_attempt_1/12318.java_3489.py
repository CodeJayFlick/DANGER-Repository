Here is the translation of the given Java code into Python:

```Python
class GenericCallingConvention:
    UNKNOWN = "unknown"
    STDCALL = CompilerSpec.CALLING_CONVENTION_STDCALL
    CDECL = CompilerSpec.CALLING_CONVENTION_CDECL
    FASTCALL = CompilerSpec.CALLING_CONVENTION_FASTCALL
    THISCALL = CompilerSpec.CALLING_CONVENTION_THISCALL
    VECTORCALL = CompilerSpec.CALLING_CONVENTION_VECTORCALL

    def __init__(self, declaration_name):
        self.declaration_name = declaration_name

    @property
    def declaration_name(self):
        return self._declaration_name

    def __str__(self):
        return self.declaration_name


class GenericCallingConventionEnum(GenericCallingConvention):
    UNKNOWN = GENERIC_CALLING_CONVENTION_UNKNOWN("")
    STDCALL = CompilerSpec.CALLING_CONVENTION_STDCALL
    CDECL = CompilerSpec.CALLING_CONVENTION_CDECL
    FASTCALL = CompilerSpec.CALLING_CONVENTION_FASTCALL
    THISCALL = CompilerSpec.CALLING_CONVENTION_THISCALL
    VECTORCALL = CompilerSpec.CALLING_CONVENTION_VECTORCALL

    def __init__(self, declaration_name):
        super().__init__(declaration_name)

    @property
    def declaration_name(self):
        return self._declaration_name


def get_generic_calling_convention(calling_convention: str) -> GenericCallingConvention:
    while calling_convention.startswith("_"):
        calling_convention = calling_convention[1:]

    for value in list(GenericCallingConventionEnum.__dict__.values()):
        if isinstance(value, type) and value.name().lower() == calling_convention.lower():
            return value

    return GenericCallingConvention.UNKNOWN


def guess_from_name(calling_convention: str) -> GenericCallingConvention:
    if not calling_convention:
        return GenericCallingConvention.UNKNOWN
    calling_convention = calling_convention.lower()
    for value in list(GenericCallingConventionEnum.__dict__.values()):
        if isinstance(value, type):
            if calling_convention.find(value.name().lower()) != -1:
                return value

    return GenericCallingConvention.UNKNOWN


def get(ordinal: int) -> GenericCallingConvention:
    values = list(GenericCallingConventionEnum.__dict__.values())
    if 0 <= ordinal < len(values):
        return values[ordinal]

    return GenericCallingConvention.UNKNOWN
```

Please note that the `CompilerSpec` class is not provided in your code, so I couldn't translate it. Also, Python doesn't support enum directly like Java does.