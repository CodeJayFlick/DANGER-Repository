class MatchAction:
    def __init__(self):
        pass

    def apply(self, program: 'Program', addr: int, match: dict) -> None:
        """Apply the match action to the program at the address."""
        # TO DO: implement this method
        pass

    def restore_xml(self, parser: object) -> None:
        """Action can be constructed from XML."""
        # TO DO: implement this method
        pass


class Program:
    pass


class Address:
    pass


class Match(dict):
    pass
