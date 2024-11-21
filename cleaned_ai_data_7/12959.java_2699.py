class TestAddress:
    SPACE = {"name": "TEST", "size": 32, "start": 0, "end": 0}

    def __init__(self, offset):
        super().__init__(offset, self.SPACE)

    def __init__(self, offset, addr_space):
        super().__init__(offset, addr_space)
