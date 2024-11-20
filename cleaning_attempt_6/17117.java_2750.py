class StorageEngineException(Exception):
    def __init__(self, message=None, cause=None, error_code=0):
        if cause:
            super().__init__(message, cause)
        elif message:
            super().__init__(message)
        else:
            super().__init__()
        self.error_code = error_code

def main():
    try:
        # some code that might raise an exception
        pass
    except StorageEngineException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
