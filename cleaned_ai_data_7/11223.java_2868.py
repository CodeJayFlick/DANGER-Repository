class ExtensionException(Exception):
    def __init__(self, message, exception_type=None, error_file=None):
        super().__init__(message)
        self.exception_type = exception_type
        self.error_file = error_file


class ExtensionExceptionType:
    INVALID_INSTALL_LOCATION = "Invalid install location"
    DUPLICATE_FILE_ERROR = "Duplicate file error"
    ZIP_ERROR = "Zip extraction error"
    COPY_ERROR = "Copy operation failed"
    INSTALL_CANCELLED = "Installation cancelled"


def main():
    try:
        # Your code here
        pass
    except ExtensionException as e:
        print(f"Error: {e}")
