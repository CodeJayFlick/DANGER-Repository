Here is the translation of the given Java code into Python:

```Python
class SimplePropertyExpression:
    def __init__(self):
        pass
    
    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parse_result: dict) -> bool:
        self.expr = exprs[0]
        return True

    @abstractmethod
    def get_property_name(self) -> str:
        pass

    @abstractmethod
    def convert(self, f: any) -> any:
        pass

    def get(self, e: dict, source: list) -> list:
        return super().get(source, self)

    def __str__(self, e: dict = None, debug: bool = False) -> str:
        if e is not None and debug:
            return f"the {self.get_property_name()} of {self.expr.__str__(e, debug)}"
        else:
            return f"the {self.get_property_name()} of {self.expr}"
```

Please note that Python does not support generics like Java. Therefore, I have removed the type parameters `F` and `T`. Also, in Python, we do not need to explicitly define a constructor as it is automatically created by the class definition.