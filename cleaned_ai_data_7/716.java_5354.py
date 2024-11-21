class DbgExceptionFilterImpl:
    def __init__(self, index, text, cmd, cmd2, execution_option, continue_option, exception_code):
        self.cmd2 = cmd2
        self.exception_code = exception_code
        super().__init__(index, text, cmd, None, execution_option, continue_option)

    @property
    def second_cmd(self):
        return self.cmd2

    @property
    def exception_code_hex(self):
        return hex(self.exception_code)
