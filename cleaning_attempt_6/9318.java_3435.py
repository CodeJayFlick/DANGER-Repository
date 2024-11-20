class SharedDockingActionPlaceholder:
    def __init__(self):
        pass

    def get_name(self) -> str:
        """The action name."""
        raise NotImplementedError("Subclasses must implement this method")

    def get_owner(self) -> str:
        """Returns an owner name to use in place of ToolConstants.SHARED_OWNER.
           This should only be used when the client knows for certain that all shared actions are 
           shared by a single owner.  This is not typical for shared actions."""
        return "SHARED_OWNER"

    def get_key_binding(self) -> object:
        """The default key binding for the action represented by this placeholder"""
        return None
