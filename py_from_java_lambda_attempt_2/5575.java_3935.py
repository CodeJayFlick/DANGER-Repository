Here is the translation of the Java code to Python:
```
class ListingHoverProvider:
    def __init__(self):
        super().__init__("ListingHoverProvider")

    def add_hover_service(self, hover_service):
        super().add_hover_service(hover_service)

    def remove_hover_service(self, hover_service):
        super().remove_hover_service(hover_service)

    def get_hover_location(self, field_location: 'FieldLocation', field: 'Field',
                            field_bounds: tuple[int, int], event: dict) -> tuple[None, None]:
        loc = None
        if isinstance(field, ListingField):
            listing_field = field  # type: ignore
            row = field_location.get_row()
            col = field_location.get_col()
            loc = (row, col)
        return loc

class FieldLocation:
    def __init__(self, row: int, col: int):
        self.row = row
        self.col = col

class ListingField:
    pass  # no equivalent in Python, just a placeholder for the Java class

# Note: In Python, we don't need to define separate classes for Rectangle and ProgramLocation,
# as they are not used explicitly in this code. We can simply use tuples or dictionaries
# to represent these concepts.
```
Note that I've made some simplifications and assumptions while translating the code:

* The `Rectangle` class is not needed, so it's omitted.
* The `ProgramLocation` class is also not needed, as its methods are not used in this code. Instead, we can use tuples or dictionaries to represent program locations.
* The `ListingHoverService`, `AbstractHoverProvider`, and other Java classes that were imported from external packages have been replaced with equivalent Python constructs (e.g., inheritance from a base class).
* Some method signatures may need adjustments depending on the specific requirements of your application.

This code should give you a good starting point for implementing the same functionality in Python.