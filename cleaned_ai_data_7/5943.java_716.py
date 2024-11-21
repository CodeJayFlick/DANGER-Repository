class OutgoingReferenceEndpoint:
    def __init__(self, reference: Reference, is_offcut=False):
        super().__init__(reference, reference.to_address(), reference.reference_type, is_offcut, reference.source)

    @classmethod
    def from_reference(cls, reference: Reference, to_address=None, is_offcut=False) -> 'OutgoingReferenceEndpoint':
        if to_address is None:
            return cls(reference, reference.get_to_address(), is_offcut)
        else:
            return cls(reference, to_address, is_offcut)

    def __str__(self):
        return f"Outgoing {self.reference_type.name}"
