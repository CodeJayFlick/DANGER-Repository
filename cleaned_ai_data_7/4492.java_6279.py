class MatchSet:
    def __init__(self, this_program_name: str, other_program_name: str):
        self.thisName = this_program_name
        self.otherName = other_program_name
        super().__init__()

    def get_matches(self) -> list:
        theMatches = list(self)
        return sorted(theMatches)

    def get_results_array(self, m: 'Match') -> list:
        a = [m.get_this_beginning(), 
             self.thisName,
             m.get_other_beginning(),
             self.otherName,
             len(m)]
        return a


class Match:
    pass  # This class is not defined in the given Java code
