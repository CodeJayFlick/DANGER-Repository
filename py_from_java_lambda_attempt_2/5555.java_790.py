Here is the translation of the Java code to Python:
```
class FieldHeaderLocation:
    def __init__(self, model: 'FieldFormatModel', factory: 'FieldFactory', row: int, col: int):
        self.model = model
        self.factory = factory
        self.row = row
        self.col = col

    @property
    def row(self) -> int:
        return self._row

    @row.setter
    def row(self, value: int):
        self._row = value

    @property
    def column(self) -> int:
        return self._col

    @column.setter
    def column(self, value: int):
        self._col = value

    @property
    def model(self) -> 'FieldFormatModel':
        return self._model

    @model.setter
    def model(self, value: 'FieldFormatModel'):
        self._model = value

    @property
    def factory(self) -> 'FieldFactory':
        return self._factory

    @factory.setter
    def factory(self, value: 'FieldFactory'):
        self._factory = value
```
Note that I used Python's built-in `class` keyword to define the class, and the `__init__` method is equivalent to Java's constructor. The rest of the methods are property getters/setters using Python's built-in `@property` decorator.

Also, note that in Python, we don't need explicit getter and setter methods like Java does with `getRow()` and `setRow()`. Instead, we use Python's attribute access syntax (`self._row = value`) to set the attributes.