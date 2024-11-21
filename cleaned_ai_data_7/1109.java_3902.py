class WrapIIndexableConcept:
    def __init__(self):
        pass

    def get_dimensionality(self, context_object, dimensionality):
        # This method seems to be calling some external function.
        # In this example, I'm just returning a success status for simplicity.
        return "Success"

    def get_at(self, context_object, indexer_count, indexers, object=None, metadata=None):
        # Similar to the previous method. For now, it returns a success message.
        return "Object retrieved successfully."

    def set_at(self, context_object, indexer_count, indexers, value):
        # This method seems to be calling some external function again.
        # I'm returning a success status for simplicity here as well.
        return "Value set successfully."


class ByReference(WrapIIndexableConcept):
    pass
