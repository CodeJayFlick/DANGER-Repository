class Output:
    def __init__(self):
        self.code = 200
        self.message = "OK"

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message

    @property
    def code(self) -> int:
        return self._code

    @code.setter
    def code(self, value: int):
        self._code = value

    @property
    def message(self) -> str:
        return self._message

    @message.setter
    def message(self, value: str):
        self._message = value


# Example usage:

output1 = Output()
print(output1.code)  # prints 200
print(output1.message)  # prints OK

output2 = Output(404, "Not Found")
print(output2.code)  # prints 404
print(output2.message)  # prints Not Found
