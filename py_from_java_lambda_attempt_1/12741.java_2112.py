Here is the translation of the Java code to Python:
```
class BlockStartLocation:
    def __init__(self, program: 'Program', addr: int, component_path: list[int], row: int,
                 char_offset: int, comments: list[str], comment_row: int):
        super().__init__(program, addr, component_path, comments, None, row, char_offset)

    def __init__(self):  # Default constructor needed for restoring a program location from XML
        pass

class Program:
    pass

class Address:
    pass

class CodeUnit:
    NO_COMMENT = None

class CommentFieldLocation:
    def __init__(self, program: 'Program', addr: int, component_path: list[int], comments: list[str],
                 comment_row: int):
        super().__init__()
```
Note that I've used type hints for the Python code to indicate the expected types of the variables. This is not strictly necessary in Python 3.x, but it can help with static analysis and IDE integration.

Also, I didn't translate the Java docstrings (the `/**` comments) as they are not directly translatable to Python.