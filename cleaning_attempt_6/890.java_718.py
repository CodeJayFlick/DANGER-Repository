class ComparableConcept:
    def __init__(self):
        pass

    def compare_objects(self, context_object: 'ModelObject', other_object: 'ModelObject') -> int:
        """A wrapper for IComparableConcept and its newer variants."""
        # Your implementation here
        return 0


from abc import ABC, abstractmethod

class Concept(ABC):
    @abstractmethod
    def __init__(self):
        pass


class ModelObject:
    def __init__(self):
        pass
