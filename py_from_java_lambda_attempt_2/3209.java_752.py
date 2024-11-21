Here is the translation of the given Java code into Python:

```Python
class SetVariableCommentCmd:
    def __init__(self, var: str, comment: str):
        self.var = var
        self.comment = comment
        self.msg = ""

    @property
    def name(self) -> str:
        return "Set Variable Comment"

    def apply_to(self, obj: dict) -> bool:
        if isinstance(obj.get("var"), dict):
            obj["var"]["comment"] = self.comment
        else:
            raise ValueError("Invalid variable object")
        return True

    @property
    def status_msg(self) -> str:
        return self.msg
```

Please note that Python does not have direct equivalent of Java's `DomainObject` and `Command`. In the above code, I used a dictionary (`dict`) to represent the DomainObject. Also, in Python, we do not need explicit getters and setters like in Java; instead, we can use properties (which are essentially getter-setter pairs).