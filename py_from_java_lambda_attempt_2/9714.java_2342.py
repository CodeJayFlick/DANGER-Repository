Here is the translation of the Java code to Python:
```
class AddRemoveListItem:
    class Type(enum.Enum):
        ADD = 1
        REMOVE = 2
        CHANGE = 3

    def __init__(self, type: 'Type', value) -> None:
        self.type = type
        self.value = value

    @property
    def is_add(self) -> bool:
        return self.type == AddRemoveListItem.Type.ADD

    @property
    def is_remove(self) -> bool:
        return self.type == AddRemoveListItem.Type.REMOVE

    @property
    def is_change(self) -> bool:
        return self.type == AddRemoveListItem.Type.CHANGE

    @property
    def type(self) -> 'Type':
        return self.type

    @property
    def value(self) -> object:
        return self.value

    def __str__(self) -> str:
        return f"{{\n\tvalue: {self.value},\n\ttype: {self.type}\n}}"
```
Note that I used the `enum.Enum` class from Python's standard library to define the `Type` enum, and I also used type hints for the method parameters. Additionally, I replaced the Java-style getters with Python-style properties using the `@property` decorator.