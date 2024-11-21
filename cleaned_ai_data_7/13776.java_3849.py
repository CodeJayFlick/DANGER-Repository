import unittest

class Cash:
    def __init__(self, count):
        self.count = count

    def plus(self, amount):
        self.count += amount

    def minus(self, amount):
        if self.count >= amount:
            self.count -= amount
            return True
        else:
            return False


class TestCash(unittest.TestCase):

    @unittest.skip("This test is an anti-example of AAA pattern. It needs refactoring.")
    def test_cash(self):
        cash = Cash(3)
        
        #test plus
        cash.plus(4)
        self.assertEqual(cash.count, 7)

        #test minus
        cash = Cash(8)
        self.assertTrue(cash.minus(5))
        self.assertEqual(cash.count, 3)
        self.assertFalse(cash.minus(6))
        self.assertEqual(cash.count, 3)

        #test update
        cash.plus(5)
        self.assertTrue(cash.minus(5))
        self.assertEqual(cash.count, 3)


if __name__ == '__main__':
    unittest.main()
