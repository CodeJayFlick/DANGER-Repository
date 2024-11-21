class TestDebuggerModelFactory:
    FAKE_DETAILS = "A 'connection' to a fake debugger"
    FAKE_DETAILS_HTML = "<html><b>Description:</b> A&nbsp;'connection '&nbsp;to&nbsp;a&nbsp;fake&nbsp;debugger</html>"
    FAKE_OPTION_NAME = "Test String"
    FAKE_DEFAULT = "Default test string"

    def __init__(self):
        self.build_queue = []

    @property
    def test_string_option(self):
        return {"name": TestDebuggerModelFactory.FAKE_OPTION_NAME, 
                "default": TestDebuggerModelFactory.FAKE_DEFAULT}

    _test_string = TestDebuggerModelFactory.FAKE_DEFAULT

    @property
    def test_string(self):
        return self._test_string

    @test_string.setter
    def test_string(self, value):
        self._test_string = value

    def build(self):
        future = {"result": None}
        self.build_queue.append(future)
        return future

    def poll_build(self):
        if not self.build_queue:
            return None
        else:
            return self.build_queue.pop(0)

