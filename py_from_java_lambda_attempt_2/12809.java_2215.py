Here is the translation of the Java code into Python:

```Python
class RefRepeatCommentFieldLocation:
    def __init__(self, program: 'Program', addr: int, component_path: list[int], 
                 comment: str, row: int, char_offset: int, current_comment_row: int, ref_repeat_address: 'Address'):
        super().__init__(program, addr, component_path, comment, 0, row, char_offset)
        self.current_comment_row = current_comment_row
        self.ref_repeat_address = ref_repeat_address

    def __init_default(self):
        super().__init__()

    @property
    def referenced_repeatable_address(self) -> 'Address':
        return self.ref_repeat_address

    @property
    def current_comment_row_(self) -> int:
        return self.current_comment_row

    def to_dict(self) -> dict:
        d = super().to_dict()
        d['currentCommentRow'] = self.current_comment_row
        if self.ref_repeat_address is not None:
            d['_refRepeatAddress'] = str(self.ref_repeat_address)
        else:
            d['_refRepeatAddress'] = ''
        return d

    def from_dict(self, data: dict):
        super().from_dict(data)
        self.current_comment_row = data['currentCommentRow']
        if '_refRepeatAddress' in data and data['_refRepeatAddress']:
            self.ref_repeat_address = Address(int(data['_refRepeatAddress']))
```

Please note that Python does not have direct equivalent of Java's `equals` method. Instead, you can override the `__eq__` method to achieve similar functionality.

Also, I did not translate all methods from the original code as some are specific to Java and do not have a direct translation in Python (like `hashCode`, `restoreState`, `saveState`).