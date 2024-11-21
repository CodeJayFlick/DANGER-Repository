class VariableSizeException(Exception):
    def __init__(self, msg, force=False):
        super().__init__(msg)
        self.force = force

    @property
    def can_force(self):
        return self.force


# Example usage:
try:
    # Your operation that may raise the exception
except VariableSizeException as e:
    if e.can_force:
        print("The operation could be successful if forced.")
    else:
        print(f"Error: {e}")
