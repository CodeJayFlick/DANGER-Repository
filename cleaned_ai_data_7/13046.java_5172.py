class AssertException(Exception):
    def __init__(self, *args, **kwargs):
        if len(args) == 0:
            super().__init__("Unexpected Error")
        elif len(args) == 1 and isinstance(args[0], str):
            super().__init__(args[0])
        else:
            message = "Unexpected Error: "
            if args[0] is not None and hasattr(args[0], 'message'):
                message += (str(args[0].getMessage()) if args[0].getMessage() is not None 
                            else str(args[0]))
            elif len(str(args)) > 0:
                message += str(args)
            super().__init__(message, *args)

    def __init__(self, message: str = "Unexpected Error", throwable=None):
        super().__init__(message, throwable)
