from collections import defaultdict, OrderedDict

class FidPopulateResult:
    class Disposition(enum.Enum):
        INCLUDED = 1
        IS_THUNK = 2
        FAILED_FUNCTION_FILTER = 3
        FAILS_MINIMUM_SHORTHASH_LENGTH = 4
        NO_DEFINED_SYMBOL = 5
        MEMORY_ACCESS_EXCEPTION = 6
        DUPLICATE_INFO = 7

    def __init__(self, library_record):
        self.library_record = library_record
        self.extreme_failure_map = defaultdict(dict)
        self.unresolved_symbols = []
        self.max_child_refs = []

    def disposition(self, domain_file, function_name, function_entry_point, disposition):
        if disposition == FidPopulateResult.Disposition.FAILED_FUNCTION_FILTER or \
           disposition == FidPopulateResult.Disposition.FAILS_MINIMUM_SHORTHASH_LENGTH:
            return
        elif disposition == FidPopulateResultDisposition.INCLUDED:
            self.num_included += 1
            return

        if disposition in [FidPopulateResult.Disposition.MEMORY_ACCESS_EXCEPTION, 
                           FidPopulateResult.Disposition.NO_DEFINED_SYMBOL]:
            break

        self.extreme_failure_map[Location(domain_file, function_name, function_entry_point)] = disposition
        total_disposition += 1

    def add_unresolved_symbol(self, function_name):
        self.unresolved_symbols.append(Location(None, function_name, None))

    @property
    def library_record(self):
        return self._library_record

    @library_record.setter
    def library_record(self, value):
        self._library_record = value

    def get_results(self):
        return dict(self.extreme_failure_map)

    def get_total_added(self):
        return self.num_included

    def get_total_excluded(self):
        return total_disposition - self.num_included

    def get_total_attempted(self):
        return total_disposition

    def get_failures(self):
        failures = {}
        for disposition in FidPopulateResult.Disposition:
            if disposition != FidPopulateResultDisposition.INCLUDED:
                failures[disposition] = getattr(self, f'num_{disposition.name.lower()}')
        return failures

    def get_unresolved_symbols(self):
        return self.unresolved_symbols[:]

    @property
    def max_child_refs(self):
        return self._max_child_refs

    @max_child_refs.setter
    def max_child_refs(self, value):
        self._max_child_refs = value

    def add_child_references(self, max, child_histogram):
        resort = sorted(child_histogram.values(), reverse=True)
        for count in resort:
            if len(self.max_child_refs) >= max:
                break
            self.max_child_refs.append(count)

class Location:
    def __init__(self, domain_file, function_name, function_entry_point):
        self.domain_file = domain_file
        self.function_name = function_name
        self.function_entry_point = function_entry_point

class Count:
    def __init__(self, name, count, is_very_common=False):
        self.name = name
        self.count = count
        self.is_very_common = is_very_common

    def __lt__(self, other):
        if self.count == other.count:
            return self.name < other.name
        else:
            return self.count > other.count
