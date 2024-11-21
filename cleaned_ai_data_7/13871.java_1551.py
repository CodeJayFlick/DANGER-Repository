import unittest
from datetime import datetime, timedelta

class DefaultCircuitBreaker:
    def __init__(self, service=None, failure_threshold=1, retry_time_period=100):
        self.service = service
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"
        self.failure_threshold = failure_threshold
        self.retry_time_period = retry_time_period

    def evaluate_state(self):
        if self.failure_count >= self.failure_threshold:
            if datetime.now() - timedelta(microseconds=self.retry_time_period) > self.last_failure_time:
                return "OPEN"
            else:
                return "HALF_OPEN"
        else:
            return "CLOSED"

    def set_state_for_bypass(self, state):
        self.state = state

    def attempt_request(self):
        if self.state == "OPEN":
            raise RemoteServiceException("Remote Service Exception")
        elif self.state == "HALF_OPEN" and datetime.now() - timedelta(microseconds=self.retry_time_period) > self.last_failure_time:
            return self.service.call()
        else:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.set_state_for_bypass("OPEN")
            raise RemoteServiceException("Remote Service Exception")

class TestDefaultCircuitBreaker(unittest.TestCase):
    def test_evaluate_state(self):
        circuit_breaker = DefaultCircuitBreaker(None, 4, 100)
        # Right now, failureCount<failureThreshold, so state should be closed
        self.assertEqual(circuit_breaker.evaluate_state(), "CLOSED")
        circuit_breaker.failure_count = 4
        circuit_breaker.last_failure_time = datetime.now()
        self.assertEqual(circuit_breaker.evaluate_state(), "HALF_OPEN")
        # Since failureCount>failureThreshold, and lastFailureTime is much lesser current time,
        # state should be open
        circuit_breaker.last_failure_time -= timedelta(microseconds=1000*1000*1000)
        self.assertEqual(circuit_breaker.evaluate_state(), "OPEN")
        # Now set it back again to closed to test idempotency
        circuit_breaker.failure_count = 0
        self.assertEqual(circuit_breaker.evaluate_state(), "CLOSED")

    def test_set_state_for_bypass(self):
        circuit_breaker = DefaultCircuitBreaker(None, 1, 2000*1000*1000)
        # Right now, failureCount<failureThreshold, so state should be closed
        # Bypass it and set it to open
        circuit_breaker.set_state_for_bypass("OPEN")
        self.assertEqual(circuit_breaker.state, "OPEN")

    def test_api_responses(self):
        class MockService:
            def call(self) -> str:
                return "Remote Success"

        service = MockService()
        circuit_breaker = DefaultCircuitBreaker(service, 1, 100)
        # Call with the parameter start_time set to huge amount of time in past so that service
        # replies with "Ok". Also, state is CLOSED in start
        response = circuit_breaker.attempt_request()
        self.assertEqual(response, "Remote Success")

if __name__ == "__main__":
    unittest.main()
