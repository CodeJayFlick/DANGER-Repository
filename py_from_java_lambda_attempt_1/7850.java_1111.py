Here's your Java code translated into Python:

```Python
class MDFunctionIndirectType:
    def __init__(self):
        self.modifier_type_name = ""

    def parse_internal(self) -> None:
        cv_mod.set_other_type()
        cv_mod.clear_properties()
        cv_mod.set_is_function()
        super().parse_internal()

    def insert(self, builder: str) -> None:
        dmang.append_string(builder, self.modifier_type_name)
        super().insert(builder)

class MDMang:
    @staticmethod
    def append_string(builder: str, string_to_append: str) -> None:
        pass

class MDException:
    pass

cv_mod = object()  # Assuming cv_mod is an instance of some class that has these methods.
dmang = MDMang()
```

Please note that this translation assumes `MDMangler`, `mdemangler.datatype.modifier.MDModifierType` and other classes are not present in the original Java code, as they were removed for brevity's sake during the translation process.