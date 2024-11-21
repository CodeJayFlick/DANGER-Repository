class IfTests:
    def test_boolean(self, x: bool) -> int:
        if x:
            return 1
        else:
            return 0

    def test_byte(self, x: bytes) -> int:
        if not x:
            return 1
        else:
            return 0

    def test_char(self, x: str) -> int:
        if not x:
            return 1
        else:
            return 0

    def test_short(self, x: int) -> int:
        if not x:
            return 1
        else:
            return 0

    def loop(self, x: bool):
        while x:
            pass

    def infinite_loop(self):
        while True:
            pass

    def add_shorts(self, a: int, b: int) -> int:
        return a + b

    def is_even(self, x: int) -> bool:
        return x % 2 == 0
