class RethrowContinuesFactory:
    INSTANCE = RethrowContinuesFactory()

    def __init__(self):
        super().__init__(RethrowExceptionHandler.INSTANCE)

# Note: In Python, we don't need a `public` keyword as it's assumed that all classes and methods are public unless explicitly marked private.
