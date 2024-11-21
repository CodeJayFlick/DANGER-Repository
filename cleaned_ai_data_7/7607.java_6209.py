class FidHashQuad:
    def __init__(self):
        pass

    @property
    def code_unit_size(self):
        """Returns the actual number of code units used to compute the full hash value."""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def full_hash(self):
        """Returns the full hash value."""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def specific_hash_additional_size(self):
        """Returns the ADDITIONAL number of code units, past the number used for the full hash,
           used to compute the specific hash value."""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def specific_hash(self):
        """Returns the specific hash value."""
        raise NotImplementedError("Subclasses must implement this method")
