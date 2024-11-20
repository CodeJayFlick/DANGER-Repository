Here is the translation of the given Java code into Python:

```Python
import logging
from typing import Any

# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class CustomerNotFoundException(Exception):
    pass


def find_customer(customer_id: str, exception: Exception = None) -> int:
    if exception is not None and isinstance(exception, CustomerNotFoundException):
        raise exception
    # Simulate the operation that looks up a customer's record and returns its ID.
    return 1234567890


class BusinessOperation:
    def __init__(self, op: Any):
        self.op = op

    def perform(self) -> int:
        try:
            result = find_customer("123")
            logging.info(f"Sometimes the operation executes with no errors. The customer ID is {result}.")
            return result
        except CustomerNotFoundException as e:
            logging.info(f"Yet the operation will throw an error every once in a while: {e}")
            raise


class Retry(BusinessOperation):
    def __init__(self, op: Any, max_attempts: int = 3, delay_between_attempts: float = 0.1,
                 predicate: callable = lambda e: isinstance(e, CustomerNotFoundException)):
        super().__init__(op)
        self.max_attempts = max_attempts
        self.delay_between_attempts = delay_between_attempts
        self.predicate = predicate

    def perform(self) -> int:
        for _ in range(self.max_attempts):
            try:
                return super().perform()
            except CustomerNotFoundException as e:
                if not self.predicate(e):
                    raise
                logging.info(f"Retrying the operation after {self.delay_between_attempts} seconds.")
                import time
                time.sleep(self.delay_between_attempts)
        else:
            raise


class RetryExponentialBackoff(Retry):
    def __init__(self, op: Any, max_attempts: int = 6, initial_delay: float = 1.0,
                 factor: float = 2.0, predicate: callable = lambda e: isinstance(e, CustomerNotFoundException)):
        super().__init__(op, max_attempts, initial_delay, predicate)
        self.factor = factor

    def perform(self) -> int:
        delay = self.initial_delay
        for _ in range(self.max_attempts):
            try:
                return super().perform()
            except CustomerNotFoundException as e:
                if not self.predicate(e):
                    raise
                logging.info(f"Retrying the operation after {delay} seconds.")
                import time
                time.sleep(delay)
                delay *= self.factor
        else:
            raise


def main() -> None:
    logging.basicConfig(level=logging.INFO)

    no_errors()
    error_no_retry()
    error_with_retry()
    error_with_retry_exponential_backoff()


def no_errors() -> None:
    op = BusinessOperation(find_customer("123"))
    result = op.perform()
    logging.info(f"Sometimes the operation executes with no errors. The customer ID is {result}.")


def error_no_retry() -> None:
    try:
        find_customer("123", CustomerNotFoundException("not found"))
    except CustomerNotFoundException as e:
        logging.info(f"Yet the operation will throw an error every once in a while: {e}")


def error_with_retry() -> None:
    retry = Retry(find_customer("123", CustomerNotFoundException("not found")), 3, 0.1)
    result = retry.perform()
    logging.info(f"However, retrying the operation while ignoring a recoverable error will eventually yield "
                 f"the result {result} after a number of attempts.")


def error_with_retry_exponential_backoff() -> None:
    retry = RetryExponentialBackoff(find_customer("123", CustomerNotFoundException("not found")), 6, 30)
    result = retry.perform()
    logging.info(f"However, retrying the operation while ignoring a recoverable error will eventually yield "
                 f"the result {result} after a number of attempts.")


if __name__ == "__main__":
    main()

```

This Python code includes several classes and functions that are similar to their Java counterparts. The `CustomerNotFoundException` class is used as an exception type, the `find_customer` function simulates looking up a customer's record and returning its ID, the `BusinessOperation` class encapsulates the operation being performed, the `Retry` class implements retrying with a fixed delay between attempts, and the `RetryExponentialBackoff` class implements exponential backoff. The main function calls these classes' methods to demonstrate their usage.