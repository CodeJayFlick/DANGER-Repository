class ThunkFunction:
    def __init__(self):
        self.destination_function = None

    def set_destination_function(self, function):
        """Set the destination function which corresponds to this thunk."""
        self.destination_function = function

    def get_destination_function_entry_point(self):
        """Returns the current destination function entry point address."""
        return self.destination_function.entry_point if self.destination_function else None
