class ProgramDatabaseSearcher:
    def __init__(self, serviceProvider, program, start_loc, set, options, monitor):
        self.search_options = options
        self.monitor = monitor if monitor else TaskMonitor.DUMMY
        self.is_forward = options.forward()
        
        if not start_loc and not set:
            start_loc = ProgramLocation(program, min_address() if is_forward else max_address())
            
        self.initialize(serviceProvider, program, start_loc, set, options)
        self.current_address = find_next_significant_address()
        self.monitor.initialize(total_search_count)

    def search(self):
        ordered_searchers = sorted(self.searchers, key=lambda x: (x.current_record if not is_forward else max_address(),))
        
        while current_address:
            monitor.set_message(f"Checking address {current_address}")
            
            for searcher in ordered_searchers:
                if searcher.has_match(current_address):
                    return searcher.get_match()
                
            last_address = current_address
            self.update_progress(last_address, find_next_significant_address())
            current_address = None

        return None

    def update_progress(self, last_address, new_address):
        if not new_address:
            return
        
        if is_forward:
            remaining_addresses.delete(remaining_addresses.min(), last_address)
        else:
            remaining_addresses.delete(last_address, remaining_addresses.max())

        progress = total_search_count - len(list(remaining_addresses))
        self.monitor.set_progress(progress)

    def find_next_significant_address(self):
        next_address = None
        for searcher in self.searchers:
            if monitor.is_cancelled():
                return None
            
            address_to_check = searcher.next_significant_address(current_address)
            
            next_address = min(next_address, address_to_check) if is_forward else max(next_address, address_to_check)

        return next_address

    def initialize(self, serviceProvider, program, start_loc, set, options):
        self.search_options = options
        forward = options.forward()
        
        trimmed_set = adjust_search_set(program, start_loc, set, forward)
        adjusted_start = adjust_start_location(program, start_loc, trimmed_set, forward)
        remaining_addresses = AddressSet(trimmed_set)
        total_search_count = len(list(remaining_addresses))
        
        pattern = UserSearchUtils.create_search_pattern(options.text(), options.case_sensitive())
        browser_code_unit_format = BrowserCodeUnitFormat(serviceProvider, False)

        if options.search_comments():
            self.searchers.append(CommentFieldSearcher(program, adjusted_start, trimmed_set, forward, pattern, CodeUnit.PLATE_COMMENT))
            self.searchers.append(FunctionFieldSearcher(program, adjusted_start, trimmed_set, forward, pattern))

    def adjust_search_set(self, program, start_loc, set, forward):
        if not set:
            return AddressSetView(program.memory())
        
        address = start_loc.address
        trimmed_set = set
        
        if forward and address > set.min():
            trimmed_set = trim_address_set(program, set, address)
        elif not forward and address < set.max():
            trimmed_set = trim_address_set(program, set, address)

        return trimmed_set

    def adjust_start_location(self, program, start_loc, set, forward):
        if not start_loc:
            return None
        
        adjusted_start = start_loc
        min_address = set.min()
        max_address = set.max()

        if forward and start_loc.address < min_address:
            return ProgramLocation(program, min_address)
        elif not forward and start_loc.address > max_address:
            return ProgramLocation(program, max_address)

        return adjusted_start

    def trim_address_set(self, program, set, address, search_forward):
        if not set or len(set) == 0:
            return AddressSetView()

        if search_forward:
            max_address = set.max()
            
            if address > max_address:
                return AddressSetView()
            
            return set.intersect(AddressSet(program.address_factory(), address, max_address))
        else:
            min_address = set.min()
            
            if address < min_address:
                return AddressSetView()
            
            return set.intersect(AddressSet(program.address_factory(), min_address, address))

class ProgramLocation:
    def __init__(self, program, address):
        self.program = program
        self.address = address

class BrowserCodeUnitFormat:
    def __init__(self, serviceProvider, is_case_sensitive):
        pass

class AddressSetView:
    def __init__(self, set):
        self.set = set

    @property
    def min(self):
        return self.set.min()

    @property
    def max(self):
        return self.set.max()

    def intersect(self, other_set):
        return AddressSetView(set.intersection(other_set))

class CommentFieldSearcher:
    def __init__(self, program, start_loc, set, forward, pattern, code_unit_type):
        pass

    def has_match(self, address):
        pass

    def get_match(self):
        pass

class FunctionFieldSearcher:
    def __init__(self, program, start_loc, set, forward, pattern):
        pass

    def has_match(self, address):
        pass

    def get_match(self):
        pass
