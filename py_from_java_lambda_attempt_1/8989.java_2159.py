Here is a translation of the provided Java code into equivalent Python:

```Python
class EditableListingAddress:
    def __init__(self, program: 'Program', current_listing_address: int, markup_item):
        self.program = program
        self.current_listing_address = current_listing_address
        self.markup_item = markup_item

    def get_editor_panel(self) -> object:
        return ListingAddressEditorPanel()

class ListingAddressEditorPanel:
    def __init__(self):
        self.build_panel()

    def build_panel(self):
        layout = PairLayout(5, 50)
        self.address_field = AddressInput()
        self.address_field.set_address_factory(self.program.get_address_factory())
        if self.current_listing_address is not None:
            self.address_field.set_address(self.current_listing_address)

        label = GDLabel("Address: ")
        add(label)
        add(self.address_field)

    def get_address(self) -> int:
        selected_address = self.address_field.get_address()
        if selected_address is None:
            raise InvalidInputException(f"\"{self.address_field.value}\" is not a valid address.")
        if not self.program.memory.contains(selected_address):
            raise InvalidInputException(f"\"{selected_address}\" is not an address in the program.")
        return selected_address

    def set_address_panel_listener(self, listener: 'AddressEditorPanelListener'):
        self.listener = listener


class Address:
    pass
```

Please note that this translation assumes you have a `Program` class and other classes defined elsewhere.