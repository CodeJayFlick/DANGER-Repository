import time
from typing import List, Any

class BusinessException(Exception):
    pass


class Retry:
    def __init__(self,
                op: callable,
                max_attempts: int,
                delay: float,
                ignore_tests: list = None) -> None:
        self.op = op
        self.max_attempts = max_attempts
        self.delay = delay
        self.attempts = 0
        self.errors = []
        if ignore_tests is not None:
            self.test = lambda e: any(test(e) for test in ignore_tests)
        else:
            self.test = lambda e: False

    @property
    def errors(self):
        return self.errors[:]

    @property
    def attempts(self):
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
                time.sleep(self.delay)
                self.attempts += 1
