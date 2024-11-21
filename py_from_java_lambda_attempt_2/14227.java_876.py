Here is the translation of the Java code to Python:
```python
import concurrent.futures
from functools import reduce
from typing import List, Callable

class SquareNumberRequest:
    def __init__(self, number: int):
        self.number = number

    def delayed_squaring(self, consumer: 'Consumer') -> None:
        # simulate long-running operation
        print(f"Squaring {self.number}...")
        result = self.number ** 2
        consumer.consume(result)
        return None


class Consumer:
    def __init__(self):
        self.sum_of_squared_numbers = 0

    def consume(self, squared_number: int) -> None:
        self.sum_of_squared_numbers += squared_number
        print(f"Consumed {squared_number}, sum is now {self.sum_of_squared_numbers}")

    def get_sum_of_squared_numbers(self) -> int:
        return self.sum_of_squared_numbers


def fan_out_fan_in(requests: List[SquareNumberRequest], consumer: Consumer) -> int:
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(req.delayed_squaring, consumer) for req in requests]
        concurrent.futures.wait(futures)

    return consumer.get_sum_of_squared_numbers()
```
Note that I've used the `concurrent.futures` module to create a thread pool and submit tasks (the `delayed_squaring` method of each `SquareNumberRequest`) to it. The `Consumer` class is similar to its Java counterpart, with methods for consuming squared numbers and getting the sum.

The `fan_out_fan_in` function takes in a list of `SquareNumberRequests` and a `Consumer`, and returns the aggregated sum of all squared numbers. It uses the thread pool to fan out the requests, and then waits for all futures to complete using `concurrent.futures.wait`.