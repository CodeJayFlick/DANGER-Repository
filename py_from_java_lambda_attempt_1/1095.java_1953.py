Here is the translation of the given Java code into equivalent Python:

```Python
class IComparableConcept:
    IID_ICOMPARABLE_CONCEPT = "A7830646-9F0C-4a31-BA19-503F33E6C8A3"

    class VTIndices:
        COMPARE_OBJECTS = 1

        @property
        def start(self):
            return self.COMPARE_OBJECTS + 2

        def get_index(self):
            return self.start


def compare_objects(context_object, other_object) -> int:
    pass  # This function is not implemented in the given Java code.