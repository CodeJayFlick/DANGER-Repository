Here is the translation of the Java code into Python:

```Python
class LabelMarkupType:
    def __init__(self):
        super().__init__("Label")

    @staticmethod
    def INSTANCE():
        return LabelMarkupType()

    def create_markup_items(self, association: 'VTAssociation') -> list['VTMarkupItem']:
        markup_items = []
        self.add_label_markup(markup_items, association)
        return markup_items

    def add_label_markup(self, markup_items: list['VTMarkupItem'], association: 'VTAssociation'):
        session = association.get_session()
        source_program = session.get_source_program()
        listing = source_program.get_listing()
        symbol_table = source_program.get_symbol_table()
        address = association.get_source_address()
        function_manager = source_program.get_function_manager()
        if not isinstance(function_manager, object):
            return
        code_unit = listing.get_code_unit_at(address)
        min_address = None
        max_address = None
        if code_unit is None:
            min_address = address
            max_address = address
        else:
            min_address = code_unit.get_min_address()
            max_address = code_unit.get_max_address()

        address_set_view = AddressSet(min_address, max_address)
        symbol_iterator = symbol_table.get_primary_symbol_iterator(address_set_view, True)

        while symbol_iterator.has_next():
            symbol = symbol_iterator.next()
            self.add_label_markup(markup_items, association, source_program, symbol.get_address())

    def get_non_default_label_markup_symbols(self, program: 'Program', address: Address) -> list['Symbol']:
        return [symbol for symbol in program.get_symbol_table().get_symbols(address)]

    def add_label_markup(self, markup_items: list['VTMarkupItem'], association: 'VTAssociation', 
                         source_program: 'Program', address: Address):
        if not self.non_default_label_markup_symbols:
            return
        final_markup_item_impl = MarkupItemImpl(association, self, address)
        markup_items.append(final_markup_item_impl)

    def remove_function_symbol(self, symbols: list['Symbol'], function_manager: object) -> list['Symbol']:
        new_list = []
        for symbol in symbols:
            if not isinstance(symbol, 'Primary') and \
               (function_manager.get_function_at(symbol.get_address()) is None):
                continue
            else:
                new_list.append(symbol)
        return [symbol for symbol in new_list]

    def apply_markup(self, markup_item: 'VTMarkupItem', options: object) -> bool:
        if not isinstance(options, object):
            raise Exception("Invalid input")
        try:
            self.remove_all_labels(get_destination_program(markup_item.get_association()), 
                                    markup_item.get_destination_address())
        except DuplicateNameException as e:
            raise VersionTrackingApplyException(f"Unable to apply symbol(s) at address {markup_item.get_destination_address()} due to a duplicate name", e)
        catch InvalidInputException as e:
            raise VersionTrackingApplyException("Unable to apply symbol(s) at address " + markup_item.get_destination_address() + " due to invalid input", e)

    def unapply_markup(self, markup_item: 'VTMarkupItem'):
        if not isinstance(markup_item, object):
            return
        try:
            self.remove_all_labels(get_destination_program(markup_item.get_association()), 
                                    markup_item.get_destination_address())
        except DuplicateNameException as e:
            raise VersionTrackingApplyException("Unable to restore symbols at address " + markup_item.get_destination_address() + " due to a duplicate name", e)
        catch InvalidInputException as e:
            raise VersionTrackingApplyException(f"Unable to restore symbols at address {markup_item.get_destination_address()} due to invalid input", e)

    def get_destination_location(self, association: 'VTAssociation', destination_address: Address) -> object:
        if not isinstance(association, object):
            return None
        program = self.get_destination_program(association)
        symbol = program.get_symbol_table().get_primary_symbol(destination_address)
        if symbol is None:
            return ProgramLocation(program, destination_address)

    def get_source_location(self, association: 'VTAssociation', source_address: Address) -> object:
        if not isinstance(association, object):
            return None
        program = self.get_source_program(association)
        symbol = program.get_symbol_table().get_primary_symbol(source_address)
        if symbol is None:
            return ProgramLocation(program, source_address)

    def get_destination_symbols(self, association: 'VTAssociation', destination_address: Address) -> list['Symbol']:
        symbols = []
        if not isinstance(destination_address, object):
            return [symbol for symbol in self.get_non_default_label_markup_symbols()]
        program = self.get_destination_program(association)
        symbols = [symbol for symbol in program.get_symbol_table().get_symbols(destination_address)]
        return symbols

    def has_same_source_and_destination_values(self, markup_item: 'VTMarkupItem') -> bool:
        if not isinstance(markup_item, object):
            return False
        source_address = markup_item.get_source_address()
        destination_address = markup_item.get_destination_address()

        # Show labels that don't yet have a destination.
        if destination_address is None or destination_address == Address.NO_ADDRESS:
            return False

        source_symbols = self.get_non_default_label_markup_symbols(self.get_source_program(markup_item.get_association()), 
                                                                     source_address)
        destination_symbols = self.get_destination_symbols(markup_item.get_association(), destination_address)

        source_names = [symbol.name for symbol in source_symbols]
        destination_names = [symbol.name for symbol in destination_symbols]

        return SystemUtilities.is_array_equal(source_names, destination_names)

    def get_symbol_names(self, symbols: list['Symbol']) -> list[str]:
        names = []
        for index, symbol in enumerate(symbols):
            if not isinstance(symbol, object):
                continue
            names.append(symbol.name)
        return [name for name in names]
```

Note that this translation is not perfect and may require some manual adjustments to work correctly.