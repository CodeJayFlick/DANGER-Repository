Here is the translation of the Java code into Python:

```Python
class VTImpliedMatchesTableModel:
    def __init__(self, controller):
        self.title = "Implied Match Table Model"
        self.controller = controller
        super().__init__(title=self.title)

    def session_changed(self):
        new_session = self.controller.get_session()
        if not new_session:
            new_session = EmptyVTSession()
        self.set_session(new_session)
        self.reload()

    def set_session(self, session):
        self.session = session
        super().set_program(session.get_source_program())
        self.reload()

    def clear(self):
        self.clear_data()

    def match_added(self, match):
        for row_object in self.get_all_data():
            if has_same_addresses(row_object, match):
                try:
                    row_object.set_match(ImpliedMatchUtils.resolve_implied_match(row_object, self.session))
                except Exception as e:
                    print(f"Error: {e}")

    def match_deleted(self, old_value):
        deleted_source_address = old_value.get_source_address()
        deleted_destination_address = old_value.get_destination_address()

        for row_object in self.get_all_data():
            if (row_object.get_source_address().equals(deleted_source_address) and
                    row_object.get_destination_address().equals(deleted_destination_address)):
                try:
                    row_object.set_match(ImpliedMatchUtils.resolve_implied_match(row_object, self.session))
                except Exception as e:
                    print(f"Error: {e}")

    def get_address(self, row):
        return self.get_row_object(row).get_source_address()

    def create_table_column_descriptor(self):
        descriptor = TableColumnDescriptor()
        descriptor.add_visible_column(SourceReferenceAddressTableColumn())
        descriptor.add_visible_column(DestinationReferenceAddressTableColumn())
        # ... other columns ...
        return descriptor

    def do_load(self, accumulator, monitor):
        match_info = self.controller.get_match_info()
        if not match_info:
            return  # no match selected
        match = match_info.get_match()
        association = match.get_association()
        source_function = self.get_source_function(association)
        destination_function = self.get_destination_function(association)

        if not (source_function and destination_function):
            return

        correlator = self.controller.get_correlator()
        matches = ImpliedMatchUtils.find_implied_matches(self.controller, source_function,
                                                           destination_function, self.session, correlator, monitor)

        monitor.set_message("Searching for existing matches...")
        monitor.initialize(len(matches))

        for implied_match in matches:
            monitor.check_canceled()

            try:
                existing_match = ImpliedMatchUtils.resolve_implied_match(implied_match, self.session)
                row_object = ImpliedMatchWrapperRowObject(implied_match, existing_match)
                accumulator.add(row_object)

                monitor.increment_progress(1)
            except Exception as e:
                print(f"Error: {e}")

    def get_source_function(self, association):
        source_program = self.session.get_source_program()
        source_address = association.get_source_address()
        function_manager = source_program.get_function_manager()
        return function_manager.get_function_at(source_address)

    def get_destination_function(self, association):
        destination_program = self.session.get_destination_program()
        destination_address = association.get_destination_address()
        function_manager = destination_program.get_function_manager()
        return function_manager.get_function_at(destination_address)


class SourceReferenceAddressTableColumn:
    def __init__(self):
        pass

    def get_column_name(self):
        return "Source Reference Address"

    def get_value(self, row_object, settings, program, service_provider):
        return str(row_object.get_source_reference_address())

    def get_column_preferred_width(self):
        return 75


class DestinationReferenceAddressTableColumn:
    def __init__(self):
        pass

    def get_column_name(self):
        return "Dest Reference Address"

    def get_value(self, row_object, settings, program, service_provider):
        return str(row_object.get_destination_reference_address())

    def get_column_preferred_width(self):
        return 75


class ImpliedMatchWrapperRowObject:
    def __init__(self, implied_match_info, match):
        self.implied_match_info = implied_match_info
        self.match = match

    @property
    def source_address(self):
        return self.implied_match_info.get_source_address()

    @property
    def destination_address(self):
        return self.implied_match_info.get_destination_address()

    @property
    def source_reference_address(self):
        return str(self.source_address)

    @property
    def destination_reference_address(self):
        return str(self.destination_address)


class EmptyVTSession:
    pass


def has_same_addresses(row_object, match):
    association = match.get_association()
    if row_object.get_source_address() != association.get_source_address():
        return False

    return row_object.get_destination_address().equals(association.get_destination_address())
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect, as some parts might need adjustments to work correctly in Python (e.g., handling exceptions).