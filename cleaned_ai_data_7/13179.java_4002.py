class LVALongTest1:
    def test1_2_long(self, a: int, b: int) -> int:
        w = a + b
        z = self.test2(w)
        return z

    def callsReturnLongIntInt(self, x: int, y: int) -> int:
        a = self.returnLongIntInt(x, y)
        return a

    def test2(self, a: int) -> int:
        return a + a

    def test3(self, a: int, b: int) -> int:
        w = a + b
        z = self.test2(w)
        return w

    def test4(self) -> int:
        z = self.test2(0x1234)
        return z

    def test5(self) -> int:
        z = self.test2(0)
        return z

    def returnLongIntInt(self, x: int, y: int) -> int:
        return 0
