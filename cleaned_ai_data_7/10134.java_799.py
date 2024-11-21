class NotOwnerException(Exception):
    """ Exception thrown if user is not the owner of a file or data object being accessed."""
    
    def __init__(self, msg="User is not the owner"):
        super().__init__(msg)
