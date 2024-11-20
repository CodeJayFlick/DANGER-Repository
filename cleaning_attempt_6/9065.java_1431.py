class MatchInfo:
    def __init__(self, controller, match, correlator):
        self.match = match
        self.correlator = correlator
        association = match.get_association()
        session = association.get_session()
        source_program = session.get_source_program()
        destination_program = session.get_destination_program()

        markup_items_cache = MarkupItemsCache()
        vt_association_type = association.get_type()

        if vt_association_type == VTAssociationType.FUNCTION:
            address_set_view = None
            data = None

            function = source_program.get_function_manager().get_function_at(association.get_source_address())
            code_unit = source_program.get_listing().get_code_unit_at(association.get_source_address())

            if code_unit is not None:
                min_address, max_address = code_unit.get_min_address(), code_unit.get_max_address()
                address_set_view = AddressSet(min_address, max_address)
            else:
                listing = source_program.get_listing()
                data = listing.get_data_at(association.get_source_address())
                code_unit = listing.get_code_unit_at(association.get_source_address())

                if code_unit is None:
                    address_set_view = AddressSet(association.get_source_address(), association.get_source_address())
                else:
                    min_address, max_address = code_unit.get_min_address(), code_unit.get_max_address()
                    address_set_view = AddressSet(min_address, max_address)

        elif vt_association_type == VTAssociationType.DATA:
            data = source_program.get_listing().get_data_at(association.get_source_address())

        destination_function = None
        if association.get_destination_address() is not None and vt_association_type == VTAssociationType.FUNCTION:
            function = destination_program.get_function_manager().get_function_at(association.get_destination_address())
            code_unit = destination_program.get_listing().get_code_unit_at(association.get_destination_address())

            if code_unit is not None:
                min_address, max_address = code_unit.get_min_address(), code_unit.get_max_address()
                address_set_view = AddressSet(min_address, max_address)
            else:
                listing = destination_program.get_listing()
                data = listing.get_data_at(association.get_destination_address())
                code_unit = listing.get_code_unit_at(association.get_destination_address())

                if code_unit is None:
                    address_set_view = AddressSet(association.get_destination_address(), association.get_destination_address())
                else:
                    min_address, max_address = code_unit.get_min_address(), code_unit.get_max_address()
                    address_set_view = AddressSet(min_address, max_address)

        self.source_function = function
        self.destination_function = destination_function

    def clear_cache(self):
        markup_items_cache.clear()

    def get_match(self):
        return self.match

    def get_source_function(self):
        return self.source_function

    def get_destination_function(self):
        return self.destination_function

    # ... rest of the methods ...

class MarkupItemsCache:
    def __init__(self, match_info=None):
        if match_info is not None:
            self.match = match_info
        else:
            self.match = MatchInfo(None, None, None)

    def get(self, monitor):
        list_ = []
        association = self.match.get_association()

        try:
            markup_items = association.get_markup_items(monitor)
            address_translator = self.match.get_address_translator(self.match.correlator)

            for markup_item in markup_items:
                destination_address = markup_item.get_destination_address()
                if destination_address is None:
                    set_default_destination(markup_item, address_translator, monitor)
                list_.append(markup_item)

            return list_
        except CancelledException as e:
            return []

    def clear(self):
        self.match.clear_cache()

def get_markup_type_for_location(program_location, program):
    if isinstance(program_location, FunctionNameFieldLocation):
        return VTMarkupType.FUNCTION_NAME
    # ... rest of the methods ...

class AddressSet:
    def __init__(self, min_address, max_address):
        self.min_address = min_address
        self.max_address = max_address

def get_markup_item(address, is_source_address, markup_type):
    if address is None:
        return None

    list_ = []
    for item in list_:
        # ... rest of the method ...

class VTMarkupType:
    FUNCTION_NAME = 1
    LABEL = 2
    EOL_COMMENT = 3
    PLATE_COMMENT = 4
    POST_COMMENT = 5
    REPEATABLE_COMMENT = 6

# ... rest of the code ...
