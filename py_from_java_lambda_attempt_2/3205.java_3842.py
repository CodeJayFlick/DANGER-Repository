Here is the translation of the given Java code into Python:

```Python
class SetFunctionRepeatableCommentCmd:
    def __init__(self, entry: str, new_repeatable_comment: str):
        self.entry = entry
        self.new_repeatable_comment = new_repeatable_comment

    @property
    def name(self) -> str:
        return "Set Function Repeatable Comment"

    def apply_to(self, obj: dict) -> bool:
        program = obj.get('program')
        function = program['listing']['function_at'](self.entry)
        if function is not None:
            function['repeatable_comment'] = self.new_repeatable_comment
        return True

    @property
    def status_msg(self) -> str:
        return ""
```

Please note that Python does not have direct equivalent of Java's `DomainObject`, `Address` and other classes. In this translation, I used Python dictionaries to represent the objects in a simplified way.