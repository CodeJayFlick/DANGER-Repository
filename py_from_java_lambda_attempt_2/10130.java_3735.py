Here is the translation of the Java code to Python:
```
class UserAccessException(Exception):
    """Exception thrown when a user requests some operation but does not have sufficient privileges."""

    def __init__(self, message="User has insufficient privilege for operation."):
        super().__init__(message)

def main():
    try:
        # Example usage
        raise UserAccessException("You don't have permission to do that!")
    except UserAccessException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```
Note that in Python, we use the built-in `Exception` class instead of creating a custom exception class. We also define a constructor (`__init__`) to set the message for the exception.

The rest of the code is just an example usage and error handling.