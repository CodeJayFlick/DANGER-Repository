# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class BookDuplicateException(Exception):
    def __init__(self, message):
        super().__init__(message)
