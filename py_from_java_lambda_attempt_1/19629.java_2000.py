Here is the translation of the given Java code into Python:

```Python
class ExprMaxStack:
    def __init__(self):
        self.registered = False

    @staticmethod
    def register():
        if not ExprMaxStack.registered:
            ExprMaxStack.registered = True
            return "max[imum] stack[[  ]size], itemtype"
        else:
            return None

    def convert(self, i: 'ItemType') -> int:
        return i.get_random().get_max_stack_size()

    @property
    def return_type(self) -> type:
        from typing import Union
        return Union[int]

    @property
    def property_name(self) -> str:
        return "maximum stack size"
```

Please note that this is a Python translation of the given Java code. The original Java class was part of Skript, which seems to be some kind of scripting language for Minecraft.