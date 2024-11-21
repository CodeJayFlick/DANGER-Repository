import threading
import time
from concurrent.futures import ThreadPoolExecutor
import logging

logging.basicConfig(level=logging.ERROR)

class CallsCount:
    def __init__(self):
        self.calls = 0

    def increment(self):
        self.calls += 1


class Tenant:
    def __init__(self, name, limit, calls_count):
        self.name = name
        self.limit = limit
        self.calls_count = calls_count

    def dummy_customer_api(self):
        # This is a placeholder for the actual API call.
        pass


class ThrottleTimerImpl:
    def __init__(self, max_calls_per_second, calls_count):
        self.max_calls_per_second = max_calls_per_second
        self.calls_count = calls_count

    def check_throttling(self):
        if self.calls_count.increment() > self.max_calls_per_second:
            time.sleep(1 / self.max_calls_per_second)


def make_service_calls(tenant, calls_count):
    timer = ThrottleTimerImpl(10, calls_count)
    service = B2BService(timer, calls_count)

    for i in range(20):
        with timer.check_throttling():
            service.dummy_customer_api()
        time.sleep(1)


class B2BService:
    def __init__(self, throttle_timer_impl, calls_count):
        self.throttle_timer_impl = throttle_timer_impl
        self.calls_count = calls_count

    def dummy_customer_api(self, tenant):
        # This is a placeholder for the actual API call.
        pass


def main():
    calls_count = CallsCount()
    adidas = Tenant("Adidas", 5, calls_count)
    nike = Tenant("Nike", 6, calls_count)

    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(make_service_calls, adidas, calls_count)
        executor.submit(make_service_calls, nike, calls_count)


if __name__ == "__main__":
    main()
