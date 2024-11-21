class InvalidLink:
    def __init__(self):
        pass

    def __lt__(self, other):
        raise NotImplementedError("compareTo not implemented")

    def __str__(self):
        return ""

    def __hash__(self):
        raise NotImplementedError("hashCode not implemented")

    def __eq__(self, obj):
        if isinstance(obj, InvalidLink):
            return False
        else:
            return NotImplemented

    @property
    def source_file(self):
        pass  # Replace with actual implementation

    @property
    def line_number(self):
        pass  # Replace with actual implementation

    def identity_hash_code(self):
        raise NotImplementedError("identityHashCode not implemented")
