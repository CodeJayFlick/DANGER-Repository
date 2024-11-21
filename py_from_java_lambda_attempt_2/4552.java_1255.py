Here is the translation of the Java code to Python:
```
class MarkerDescriptor:
    def __init__(self):
        pass

    def get_program_location(self, loc: 'MarkerLocation') -> 'ProgramLocation':
        return None

    def get_tooltip(self, loc: 'MarkerLocation') -> str:
        return None

    def get_icon(self, loc: 'MarkerLocation') -> 'ImageIcon':
        return None
```
Note that I've used Python's type hints to indicate the types of the method parameters and return values. This is not strictly necessary for a working translation, but it can be helpful for readability and documentation purposes.

Also, in Python, we don't need an explicit `public` access modifier like Java does. The default visibility is public, so I've omitted that keyword altogether.