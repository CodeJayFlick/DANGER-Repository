Here is the translation of the given Java code into Python:

```Python
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
```

Please note that I've used type hints for clarity, but Python does not have built-in support for generics like Java. Also, since `Match` and its methods are not provided in the original Java code, I left them as placeholders (`pass`) in the translated Python code.