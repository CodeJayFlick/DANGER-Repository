# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class CustomerNotFoundException(Exception):
    """Indicates that the customer was not found.

    Severity of this error is bounded by its context: was the search for the customer triggered by an input from some end user, or were the search parameters pulled from your database?
    """

    def __init__(self, message):
        super().__init__(message)

# Example usage:
try:
    # code that might raise CustomerNotFoundException
except CustomerNotFoundException as e:
    print(f"Error: {e}")
