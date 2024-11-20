import unittest

class SquareNumberRequestTest(unittest.TestCase):

    def test_delayed_squaring(self):
        consumer = Consumer(10)
        square_number_request = SquareNumberRequest(5)

        square_number_request.delayed_squaring(consumer)

        self.assertEqual(35, consumer.get_sum_of_squared_numbers())

if __name__ == '__main__':
    unittest.main()
