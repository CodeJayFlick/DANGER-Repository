class SearchAllSearchInfo:
    def __init__(self, search_data, match_limit, search_selection, forward_search, alignment,
                 include_non_loaded_blocks, code_unit_search_info):
        pass  # No direct equivalent in Python for super() call

    def get_searchable_address_set(self, program: 'Program', address: 'Address',
                                    selection: 'ProgramSelection'):
        memory = program.get_memory()
        set = None
        if self.include_non_loaded_blocks:
            set = memory.get_all_initialized_address_set()
        else:
            set = memory.get_loaded_and_initialized_address_set()

        if search_selection and selection is not None and not selection.is_empty():
            set = set.intersection(selection)

        return set

    def is_search_all(self):
        return True


class Program: pass
class Address: pass
class Memory: pass
class ProgramSelection: pass
