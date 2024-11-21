class MemSearcherAlgorithm:
    def __init__(self, search_info: dict, address_set_view: list, program):
        self.search_data = search_info['search_data']
        self.forward_search = search_info['forward_search']
        self.alignment = search_info['alignment']
        self.search_set = address_set_view
        self.match_limit = search_info['match_limit']
        self.program = program
        self.code_unit_search_info = search_info['code_unit_search_info']

    def search(self, accumulator: list, monitor):
        address_ranges = iter(self.search_set)
        monitor.initialize(len(self.search_set))
        progress_count = 0

        while True:
            try:
                range_ = next(address_ranges)
            except StopIteration:
                break
            if not monitor.is_cancelled():
                self.search_range(accumulator, range_, monitor, progress_count)
                progress_count += len(range_)
                monitor.set_progress(progress_count)
                if len(accumulator) >= self.match_limit:
                    return

    def search_range(self, accumulator: list, address_range, monitor, progress_count):
        memory = self.program.get_memory()
        start_address = address_range[0] if self.forward_search else address_range[-1]
        end_address = address_range[-1] if self.forward_search else address_range[0]

        length = len(self.search_data['bytes'])
        while True:
            match_address = memory.find_bytes(start_address, end_address, self.search_data['bytes'], 
                                               self.search_data.get('mask', None), self.forward_search, monitor)
            if not is_matching_address(match_address):
                break
            result = {'address': match_address, 'length': length}
            accumulator.append(result)
            if len(accumulator) >= self.match_limit:
                return

    def get_range_difference(self, address_range: list, address):
        return (int)(self.forward_search and address - address_range[0] or 
                     address_range[-1] - address)

    def is_matching_address(self, address):
        if not address:
            return False
        if (address.offset % self.alignment) != 0:
            return False

        code_unit = self.program.get_listing().get_code_unit_containing(address)
        if isinstance(code_unit, Instruction):
            return self.code_unit_search_info['search_instructions']
        elif isinstance(code_unit, Data):
            data = code_unit
            return (data.is_defined() and 
                    self.code_unit_search_info['search_defined_data']) or \
                   not data.is_defined() and self.code_unit_search_info['search_undefined_data']

    def get_next_address(self, current_address: Address, address_range: list):
        if not current_address:
            return None
        if self.forward_search:
            return (current_address == address_range[-1]) and None or current_address.next()
        else:
            return (current_address == address_range[0]) and None or current_address.previous()

    def get_search_set(self):
        return self.search_set

class AddressSetView(list): pass
