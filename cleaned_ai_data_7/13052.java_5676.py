class Fixup:
    def __init__(self):
        pass

    def get_description(self) -> str:
        """Returns a description of what this Fixup does."""
        # TO DO: implement me!
        return ""

    def can_fixup(self) -> bool:
        """Return true if this Fixup object can automatically perform some action to address the issue. False otherwise."""
        # TO DO: implement me!
        return False

    def fixup(self, provider):
        """Attempts to perform some action or task to "fix" the related issue."""
        # TO DO: implement me!
        pass
