class Pointer:
    def __init__(self):
        pass

    def get_data_type(self) -> 'DataType':
        """Returns the "pointed to" data type"""
        pass  # Implement this method in your subclass

    @classmethod
    def new_pointer(cls, data_type: 'DataType') -> 'Pointer':
        """Creates a pointer to the indicated data type."""
        return cls()  # You would need to implement how you want to create a new Pointer instance.
