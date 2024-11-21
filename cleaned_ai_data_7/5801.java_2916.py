class ProgramMemoryComparator:
    def __init__(self, program1: 'Program', program2: 'Program') -> None:
        self.program1 = program1
        self.program2 = program2
        
        if not similar_programs(program1, program2):
            raise Exception("Address spaces conflict between {} and {}".format(program1.name(), program2.name()))
        
        determine_address_diffs()

    def determine_address_diffs(self) -> None:
        init_addr_set1 = ProgramMemoryUtil.get_address_set(self.program1, True)
        uninit_addr_set1 = ProgramMemoryUtil.get_address_set(self.program1, False)

        init_addr_set2 = ProgramMemoryUtil.get_address_set(self.program2, True)
        uninit_addr_set2 = ProgramMemoryUtil.get_address_set(self.program2, False)
        
        compatible_init_addr_set2 = DiffUtility.get_compatible_address_set(init_addr_set2, self.program1)
        compatible_uninit_addr_set2 = DiffUtility.get_compatible_address_set(uninit_addr_set2, self.program1)

        uninit_in_both = init_addr_set1.intersection(compatible_uninit_addr_set2)
        
        in_both = init_addr_set1.intersection(compatible_init_addr_set2).union(uninit_in_both)
        
        only_in_one = init_addr_set1.difference(in_both)
        
        compatible_only_in_two = DiffUtility.get_compatible_address_set(only_in_two, self.program1)

    @staticmethod
    def similar_programs(p1: 'Program', p2: 'Program') -> bool:
        if not (p1 and p2):
            return False
        
        if p1.language_id == p2.language_id:
            return True

        spaces1 = [space for space in p1.get_language().get_address_spaces()]
        spaces2 = [space for space in p2.get_language().get_address_spaces()]

        if len(spaces1) != len(spaces2):
            return False
        
        sorted_spaces1 = sorted(spaces1)
        sorted_spaces2 = sorted(spaces2)

        for i, (s1, s2) in enumerate(zip(sorted_spaces1, sorted_spaces2)):
            if not s1.equals(s2):
                return False

        return True


class Program:
    def __init__(self, name: str, language_id: str) -> None:
        self.name = name
        self.language_id = language_id


def get_combined_addresses(program1: 'Program', program2: 'Program') -> set:
    addr_set1 = ProgramMemoryUtil.get_address_set(program1)
    addr_set2 = ProgramMemoryUtil.get_address_set(program2)

    compatible_addr_set2 = DiffUtility.get_compatible_address_set(addr_set2, program1)

    return addr_set1.union(compatible_addr_set2)


def get_addresses_in_common(self) -> set:
    return self.in_both


def has_memory_differences(self) -> bool:
    return not (self.only_in_one.is_empty() and self.only_in_two.is_empty())
