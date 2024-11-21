Here is the translation of the Java code to Python:
```python
import random
from typing import List, Any

class BusinessException(Exception):
    pass

class RetryExponentialBackoff:
    def __init__(self,
                 op: callable,
                 max_attempts: int,
                 max_delay: float,
                 *ignore_tests: callable) -> None:
        self.op = op
        self.max_attempts = max_attempts
        self.max_delay = max_delay
        self.attempts = 0
        self.errors = []
        self.test = all(test(e) for test in ignore_tests)

    @property
    def errors(self) -> List[Any]:
        return self.errors[:]

    @property
    def attempts(self) -> int:
        return self.attempts

    def perform(self) -> Any:
        while True:
            try:
                result = self.op()
                return result
            except BusinessException as e:
                self.errors.append(e)
                if self.attempts >= self.max_attempts or not self.test(e):
                    raise e
                delay = 2 ** (self.attempts + 1) * 1000 + random.randint(0, 999)
                delay = min(delay, self.max_delay)
                time.sleep(delay)

# Example usage:
def my_business_operation() -> int:
    # your business logic here
    return 42

op = my_business_operation
retry_op = RetryExponentialBackoff(op, max_attempts=3, max_delay=5.0,
                                      lambda e: isinstance(e, ValueError))
result = retry_op.perform()
print(result)  # prints 42 or raises an exception if retries fail
```
Note that I used the `typing` module to define type hints for the class and its methods. This is not strictly necessary in Python, but it can help with code readability and maintainability.

Also, I replaced the Java-specific constructs (e.g., `AtomicInteger`, `Predicate`) with equivalent Python idioms (e.g., using a simple integer variable instead of an atomic counter).