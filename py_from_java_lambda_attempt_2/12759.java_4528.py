Here is the translation of the Java code into Python:

```Python
class EolCommentFieldLocation:
    def __init__(self, program=None, addr=None, component_path=None, comment=None, displayable_comment_row=0, char_offset=0, current_comment_row=0):
        super().__init__(program, addr, component_path, comment, 'EOL_COMMENT', displayable_comment_row, char_offset)
        self.current_comment_row = current_comment_row

    def __str__(self):
        return f"{super().__str__()}, Comment Row = {self.current_comment_row}"

    def get_current_comment_row(self):
        return self.current_comment_row
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements, or the `@Override` annotation. Also, Python uses indentation to denote block-level structure instead of curly braces.

The code above is a simplified version of your original Java code and may need further modifications based on specific requirements.