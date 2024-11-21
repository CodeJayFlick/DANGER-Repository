class FixedField:
    def __init__(self, data=None, immutable=False):
        self.data = data if not immutable else bytes(data)
        self.is_null = False
        super().__init__()

    @property
    def is_variable_length(self):
        return False

    @property
    def is_null_(self):
        return self.is_null

    def set_null(self):
        if hasattr(self, 'is_immutable') and self.is_immutable:
            raise AttributeError("Immutable field cannot be nullified")
        self.is_null = True

    def updating_value(self):
        if hasattr(self, 'is_immutable'):
            raise AttributeError("Immutable field cannot have its value updated")
        self.is_null = False

    def truncate(self, length):
        raise NotImplementedError("Field may not be truncated")

    def copy_field(self):
        # This method should return a new instance of the same class
        pass  # To be implemented by subclasses

    def new_field(self):
        # This method should return a new instance of the same class
        pass  # To be implemented by subclasses

    @property
    def min_value(self):
        raise NotImplementedError("Min value not defined")

    @property
    def max_value(self):
        raise NotImplementedError("Max value not defined")
