Here is the translation of the Java code to Python:
```
class FieldBasedSearchLocation:
    def __init__(self, field_location: 'FieldLocation', start_index_inclusive: int,
                 end_index_inclusive: int, search_text: str, forward_direction: bool):
        super().__init__(start_index_inclusive, end_index_inclusive, search_text, forward_direction)
        self.field_location = field_location

    @property
    def field_location(self) -> 'FieldLocation':
        return self._field_location

    def get_cursor_position(self) -> 'CursorPosition':
        return DecompilerCursorPosition(self.field_location)

    def __str__(self):
        return super().__str__() + ", field_location=" + str(self.field_location)
```
Note that I used the `@property` decorator to create a read-only property for the `field_location` attribute, since there is no equivalent concept in Python as Java's getter method.