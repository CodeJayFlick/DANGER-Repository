class SleighExpression:
    RESULT_NAME = "___result"

    class ValueCapturingSleighUseropLibrary(metaclass=type):
        def __init__(self):
            self.result = None

        @property
        def result(self):
            return self._result

        @result.setter
        def result(self, value):
            self._result = value

class SleighExpression:
    def __init__(self, language, code, userop_symbols):
        pass  # equivalent to super().__init__()

    def evaluate(self, executor):
        library = ValueCapturingSleighUseropLibrary()
        execute(executor, library)
        return library.result
