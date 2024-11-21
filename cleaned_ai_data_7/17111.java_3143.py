class FlushRuntimeError(Exception):
    def __init__(self, exception: Exception):
        super().__init__(str(exception))

serialVersionUID = 2249517655460110259
