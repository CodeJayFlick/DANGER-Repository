class ScalarOverflowException(Exception):
    """A ScalarOverflowException indicates that some precision would be lost.
       If the operation was signed, unused bits did not match the sign bit.
       If the operation was unsigned, unsed bits were not all zero"""

    def __init__(self, message="Scalar overflow"):
        super().__init__(message)
