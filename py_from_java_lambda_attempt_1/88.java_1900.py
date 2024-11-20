Here is the translation of the Java code to Python:
```
class DebuggerTrackedRegisterListingBackgroundColorModel(DebuggerTrackedRegisterBackgroundColorModel):
    def __init__(self, plugin: 'Plugin', listing_panel: 'ListingPanel'):
        super().__init__(plugin)
        self.model_data_changed(listing_panel)

    @property
    def program(self) -> object:
        return None

    @program.setter
    def program(self, value: object):
        if not isinstance(value, (type(None), Program)):
            raise TypeError("Expected a Program or None")
        self._program = value

    @property
    def address_index_map(self) -> dict:
        return {}

    @address_index_map.setter
    def address_index_map(self, value: dict):
        if not isinstance(value, dict):
            raise TypeError("Expected a dictionary")
        self._address_index_map = value

    def model_data_changed(self, listing_panel: 'ListingPanel'):
        self.program = listing_panel.get_program() if listing_panel else None
        self.address_index_map = listing_panel.get_address_index_map() if listing_panel else {}
```
Note that I've used type hints to indicate the expected types of variables and method parameters. This is not strictly necessary for Python, but it can help with code readability and catch potential errors at runtime.

Also, I've assumed that `Plugin` and `ListingPanel` are classes defined elsewhere in your codebase. If they're not, you'll need to define them or import the relevant modules.