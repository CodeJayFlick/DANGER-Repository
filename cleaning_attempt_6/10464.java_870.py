class NotEmptyException(Exception):
    """exception thrown whenever some container is expected to be empty and it isn't."""
    
    def __init__(self, message="Object was occupied.") -> None:
        super().__init__(message)

if __name__ == "__main__":
    try:
        raise NotEmptyException()
    except NotEmptyException as e:
        print(e)
