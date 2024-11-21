Here is the equivalent Python code:

```Python
import unittest
from typing import List

class SquareNumberRequest:
    def __init__(self, number: int):
        self.number = number

def fan_out_fan_in(requests: List[SquareNumberRequest], consumer) -> int:
    total_sum_squared_numbers = 0
    for request in requests:
        squared_number = request.number ** 2
        consumer.consume(squared_number)
        total_sum_squared_numbers += squared_number
    return total_sum_squared_numbers

class Consumer:
    def __init__(self, initial_value: int):
        self.value = initial_value

    def consume(self, value: int) -> None:
        pass


class TestFanOutFanIn(unittest.TestCase):

    def test_fan_out_fan_in(self):
        numbers = [1, 3, 4, 7, 8]
        requests = [SquareNumberRequest(num) for num in numbers]

        consumer = Consumer(0)
        sum_of_squared_numbers = fan_out_fan_in(requests, consumer)

        self.assertEqual(sum_of_squared_numbers, 139)


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `Consumer` interface. In this code, I've created a simple class called `Consumer` with a method `consume`.