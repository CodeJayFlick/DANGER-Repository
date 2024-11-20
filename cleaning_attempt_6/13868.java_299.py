# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class RemoteServiceException(Exception):
    """ Exception thrown when `RemoteService` does not respond successfully. """
    
    def __init__(self, message: str):
        super().__init__(message)
