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
