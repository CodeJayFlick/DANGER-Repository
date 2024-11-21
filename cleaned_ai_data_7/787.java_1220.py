class DbgModelTargetSymbol:
    def is_constant(self):
        pass  # To be implemented by subclasses

    def get_value(self) -> 'Address':
        raise NotImplementedError("Method not yet implemented")

    def get_size(self) -> int:
        raise NotImplementedError("Method not yet implemented")
