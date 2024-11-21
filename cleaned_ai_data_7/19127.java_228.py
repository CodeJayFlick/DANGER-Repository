class ReferenceNotFoundException(Exception):
    def __init__(self, message):
        super().__init__(message)

def for_reference(ref: str) -> 'ReferenceNotFoundException':
    if isinstance(ref, (str)):
        return ReferenceNotFoundException(f"Ref '{ref}' does not exist")
    elif ref.startswith("refs/heads/"):
        return ReferenceNotFoundException(f"Branch '{ref}' does not exist")
    elif ref.startswith("refs/tags/"):
        return ReferenceNotFoundException(f"Tag '{ref}' does not exist")
    else:
        raise ValueError(f"Invalid reference: {ref}")

