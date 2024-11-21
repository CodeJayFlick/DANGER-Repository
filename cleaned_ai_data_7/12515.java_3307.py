class UnknownInstructionException(Exception):
    """An UnknownInstructionException indicates that the bytes at the parse address did not form a legal known instruction."""
    
    def __init__(self, message="Bytes do not form a legal instruction."):
        super().__init__(message)
