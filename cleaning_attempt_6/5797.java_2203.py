class ProgramConflictException(Exception):
    """Exception for incompatible programs when comparing programs for differences or when merging program differences."""

    def __init__(self, msg=""):
        super().__init__(msg)
