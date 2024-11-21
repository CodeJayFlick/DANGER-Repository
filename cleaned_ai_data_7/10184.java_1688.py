class RethrowExceptionHandler:
    INSTANCE = RethrowExceptionHandler()

    def __init__(self):
        pass

    def handle(self, e: Exception) -> None:
        raise e


# Note that in Python, we don't need to declare static methods or variables,
# and the `@Override` annotation is not necessary. The `raise` statement
# will re-throw the exception.
