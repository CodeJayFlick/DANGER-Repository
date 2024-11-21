class TraceEquateManager:
    def validate_name(self, name):
        if not isinstance(name, str) or len(name.strip()) == 0:
            raise ValueError("name cannot be null or empty string")
        for char in name:
            if ord(char) < 32:  # Check for whitespace characters
                raise ValueError("name cannot contain whitespace")

    def get_equate_space(self, space, create_if_absent=False):
        pass

    def get_equate_register_space(self, thread, create_if_absent=False):
        pass

    def get_equate_register_space(self, frame, create_if_absent=False):
        pass

    def create(self, name: str, value: int) -> 'TraceEquate':
        raise NotImplementedError("This method is not implemented")

    def by_name(self, name: str) -> 'TraceEquate':
        raise NotImplementedError("This method is not implemented")

    def by_key(self, key: int) -> 'TraceEquate':
        raise NotImplementedError("This method is not implemented")

    def by_value(self, value: int):
        return []

    def all(self):
        return []
