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
