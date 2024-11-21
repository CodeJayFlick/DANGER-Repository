class DataModelNameBinder:
    def bind_value(self, context_object: 'ModelObject', name: str) -> None:
        pass  # To be implemented by subclass or user

    def bind_reference(self, context_object: 'ModelObject', name: str) -> None:
        pass  # To be implemented by subclass or user

    def enumerate_values(self, context_object: 'ModelObject') -> 'KeyEnumerator':
        raise NotImplementedError("enumerate_values must be implemented")

    def enumerate_references(self, context_object: 'ModelObject') -> 'KeyEnumerator':
        raise NotImplementedError("enumerate_references must be implemented")
