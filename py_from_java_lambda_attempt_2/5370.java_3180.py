Here is a translation of the Java code into Python:

```Python
class GoToQuery:
    def __init__(self, navigatable: 'Navigatable', plugin: 'Plugin', goToService: 'GoToService',
                queryData: 'QueryData', from_address: Address, listener: 'GoToServiceListener' = None,
                navigation_options: NavigationOptions = None, monitor: TaskMonitor = None):
        self.navigatable = navigatable
        self.query_data = query_data
        self.from_address = from_address
        self.plugin = plugin
        self.go_to_service = goToService
        self.navigation_options = navigation_options if navigation_options is not None else NavigationOptions()
        self.max_hits = 1000

    def process_query(self):
        if self.process_address_expression():
            return True
        elif self.process_wild_card():
            return True
        elif self.process_symbol_in_parsed_scope():
            return True
        elif self.process_symbol_in_current_program():
            return True
        elif not self.navigation_options.is_go_to_restricted_to_current_program():
            if self.process_input_as_symbol_in_all_programs():
                return True
        if self.process_address():
            return True
        if self.process_dynamic_or_case_insensitive():
            return True

    def check_for_override(self):
        override = self.go_to_service.get_override_service()
        if override is None:
            return False
        program_location = override.go_to(self.query_data.get_query_string())
        if program_location is not None:
            self.go_to_service.go_to(self.navigatable, program_location)
            self.notify_listener(True)
            return True
        return False

    def process_address_expression(self):
        # implementation of the method
        pass

    def process_wild_card(self):
        # implementation of the method
        pass

    def process_symbol_in_parsed_scope(self):
        # implementation of the method
        pass

    def process_symbol_in_current_program(self):
        # implementation of the method
        pass

    def process_input_as_symbol_in_all_programs(self):
        # implementation of the method
        pass

    def process_address(self):
        if self.check_for_override():
            return True
        for program in self.get_all_programs():
            addresses = program.parse_address(self.query_data.get_query_string(), self.query_data.is_case_sensitive())
            valid_addresses = self.validate_addresses(program, addresses)
            if len(valid_addresses) > 0:
                self.go_to_addresses(program, valid_addresses)
                return True
        # check once more if the current location has an address for the address string.
        program = self.navigatable.get_program()
        file_address = self.get_file_address(program, self.query_data.get_query_string())
        if file_address is not None:
            self.go_to_addresses(program, [file_address])
            return True
        return False

    def process_dynamic_or_case_insensitive(self):
        # implementation of the method
        pass

    def notify_listener(self, has_data: bool):
        if self.listener is not None:
            self.listener.goto_completed(self.query_data.get_query_string(), has_data)
        else:
            Msg.show_warn(None, "Search Limit Exceeded!", f"Stopped search after finding {self.max_hits} matches.\nThe Search limit can be changed in the Edit->Options, under Tool Options")

    def go_to_addresses(self, program: Program, valid_addresses):
        if len(valid_addresses) == 1:
            self.go_to(program, valid_addresses[0], self.from_address)
            self.notify_listener(True)
            return
        SystemUtilities.run_if_swing_or_post_swing_later(lambda: model = AddressArrayTableModel("Goto:", program, valid_addresses, monitor))

    def go_to_program_locations(self, program: Program, locations):
        if len(locations) == 1:
            self.go_to(program, locations[0])
            self.notify_listener(True)
            return
        SystemUtilities.run_if_swing_or_post_swing_later(lambda: model = GoToQueryResultsTableModel("Goto:", program, plugin.get_tool(), max_hits, monitor))

    def get_all_programs(self):
        # implementation of the method
        pass

    def validate_addresses(self, program: Program, addresses):
        memory = program.get_memory()
        valid_addresses = []
        for address in addresses:
            if memory.contains(address):
                valid_addresses.append(address)
        return valid_addresses

    def get_file_address(self, program: Program, query_string):
        # implementation of the method
        pass

class DummyGoToServiceListener(GoToServiceListener):
    def goto_completed(self, query_string: str, found_results: bool):
        # stubbed
        pass

    def goto_failed(self, exc: Exception):
        # stubbed
        pass