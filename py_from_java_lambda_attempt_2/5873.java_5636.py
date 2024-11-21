Here is the translation of the given Java code into Python:

```Python
class SearchInfo:
    def __init__(self, search_data: 'SearchData', match_limit: int, 
                search_selection: bool, forward_search: bool, alignment: int,
                include_non_loaded_blocks: bool, listener: 'TaskListener') -> None:
        self.search_data = search_data
        self.match_limit = match_limit
        self.search_selection = search_selection
        self.forward_search = forward_search
        self.alignment = alignment
        self.listener = listener

    def get_searchable_address_set(self, program: 'Program', start_address: 'Address',
                                    selection: 'ProgramSelection') -> set:
        if start_address is None:
            return set()  # special case if we are at the first address going backwards or the last address going forwards
        memory = program.get_memory()
        address_set_view = include_non_loaded_blocks and memory.get_all_initialized_address_set() or memory.get_loaded_and_initialized_address_set()
        if self.search_selection and selection is not None and not selection.is_empty():
            address_set_view &= set(selection)
        start = forward_search and start_address or memory.get_min_address()
        end = forward_search and memory.get_max_address() or start_address
        if start > end:
            return set()
        address_set = program.get_address_factory().get_address_set(start, end)
        return address_set_view & address_set

    def create_search_algorithm(self, p: 'Program', start: 'Address',
                                selection: 'ProgramSelection') -> 'MemorySearchAlgorithm':
        searchable_address_set = self.get_searchable_address_set(p, start, selection)

        search_across_gaps = False
        if isinstance(search_data, RegExSearchData):
            return RegExMemSearcherAlgorithm(self, searchable_address_set, p, search_across_gaps)
        else:
            return MemSearcherAlgorithm(self, searchable_address_set, p)

    def is_search_forward(self) -> bool:
        return self.forward_search

    def is_search_all(self) -> bool:
        return False

    def get_alignment(self) -> int:
        return self.alignment

    def get_match_limit(self) -> int:
        return self.match_limit

    def get_listener(self) -> 'TaskListener':
        return self.listener

    def get_search_data(self) -> 'SearchData':
        return self.search_data

    def get_code_unit_search_info(self) -> 'CodeUnitSearchInfo':
        return self.code_unit_search_info

    def get_search_limit(self) -> int:
        return self.match_limit
```

Note: This translation assumes that the Java code is using a specific framework or library (Ghidra), which may not be directly applicable to Python. The translated Python code will need further modifications and adjustments based on your actual use case in Python.