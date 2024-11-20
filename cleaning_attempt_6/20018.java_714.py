class FieldHandler:
    def excessive_field(self, o: object, field_context: dict) -> bool:
        """Called when a loaded field doesn't exist."""
        # Your implementation here
        pass

    def missing_field(self, o: object, field: str) -> bool:
        """Called if a field was not found in the stream."""
        # Your implementation here
        pass

    def incompatible_field(self, o: object, f: dict, field_context: dict) -> bool:
        """Called when a loaded value is not compatible with the type of a field."""
        # Your implementation here
        pass
