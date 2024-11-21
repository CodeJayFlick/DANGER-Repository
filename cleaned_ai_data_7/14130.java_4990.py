# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class InvalidOperationException(Exception):
    """Type of Exception raised when the Operation being invoked is Invalid."""
    serialVersionUID = -6191545255213410803L

    def __init__(self, message: str):
        super().__init__(message)
