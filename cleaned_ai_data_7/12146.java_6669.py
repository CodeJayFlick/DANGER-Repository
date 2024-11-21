class AddressOutOfBoundsException(Exception):
    """An AddressOutOfBoundsException indicates that the Address is being used 
       to address Memory which does not exist."""
    
    def __init__(self, message="Address not contained in memory"):
        super().__init__(message)
