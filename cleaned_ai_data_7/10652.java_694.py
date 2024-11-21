import unittest


class BitTreeTest(unittest.TestCase):

    def setUp(self):
        pass

    def test_bit_tree(self):
        print("Testing put method")
        bt = BitTree(1000)
        bt.put(25)
        bt.put(234)
        bt.put(2)
        bt.put(999)
        bt.put(0)
        bt.put(700)

        print("Testing first/next methods")
        self.assertEqual(list(bt), [0, 2, 25, 234, 700, 999])

        print("Testing last/previous methods")
        self.assertEqual(list(reversed(bt)), [999, 700, 234, 25, 2, 0])

        print("Testing get_next_method")
        if bt.get_next(500) != 700:
            self.fail(f"Expected next value after 500 to be 700, but instead got {bt.get_next(500)}")

        print("Testing delete")
        bt.remove(234)
        bt.remove(2)
        bt.remove(999)
        self.assertEqual(list(bt), [0, 25, 700])
        print("Testing remove all")
        bt.remove_all()
        self.assertEqual(list(bt), [])

        print("Test puting all keys in set")
        for i in range(1000):
            bt.put(i)

        n = bt.get_first()
        for _ in range(1000):
            if n != i:
                self.fail(f"All keys failed!  n = {n} and i = {i}")
            n = bt.get_next(n)
        if n != -1:
            self.fail("Too many keys in full BitTree!")

        print("test creating BitTree full")
        bt = BitTree(1000, True)
        if bt.get_last() != 999:
            self.fail(f"Create full BitTree failed, last value = {bt.get_last()}, was expecting 999")


    def test_expect(self):
        values = [0, 2, 25, 234, 700, 999]
        k = bt.get_first()
        for i in range(len(values)):
            if k != values[i]:
                self.fail(f"Expected {values[i]} and got {k}")
            k = bt.get_next(k)
        if k != -1:
            self.fail("More values in bitTree than expected")

    def test_expect_backwards(self):
        values = [999, 700, 234, 25, 2, 0]
        k = bt.get_last()
        for i in range(len(values)):
            if k != values[i]:
                self.fail(f"Expected {values[i]} and got {k}")
            k = bt.get_previous(k)
        if k != -1:
            self.fail("More values in bitTree than expected")


if __name__ == '__main__':
    unittest.main()
