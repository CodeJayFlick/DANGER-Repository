import time
from unittest import TestCase


class AppTest(TestCase):

    def setUp(self):
        self.delayed_service = DelayedRemoteService(time.time(), 4)
        self.quick_service = QuickRemoteService()
        
        self.delayed_service_circuit_breaker = DefaultCircuitBreaker(
            delayed_service, 
            3000, 
            FAILURE_THRESHOLD,
            RETRY_PERIOD * 1000 * 1000 * 1000
        )
        
        self.quick_service_circuit_breaker = DefaultCircuitBreaker(
            quick_service, 
            3000, 
            FAILURE_THRESHOLD,
            RETRY_PERIOD * 1000 * 1000 * 1000
        )

        self.monitoring_service = MonitoringService(
            delayed_service_circuit_breaker, 
            quick_service_circuit_breaker
        )


    def test_failure_open_state_transition(self):
        # Calling delayed service, which will be unhealthy till 4 seconds
        self.assertEqual("Delayed service is down", self.monitoring_service.delayed_service_response())
        
        # As failure threshold is "1", the circuit breaker is changed to OPEN
        self.assertEqual("OPEN", self.delayed_service_circuit_breaker.get_state())

        # As circuit state is OPEN, we expect a quick fallback response from circuit breaker.
        self.assertEqual("Delayed service is down", self.monitoring_service.delayed_service_response())
        
        # Meanwhile, the quick service is responding and the circuit state is CLOSED
        self.assertEqual("Quick Service is working", self.monitoring_service.quick_service_response())
        self.assertEqual("CLOSED", self.quick_service_circuit_breaker.get_state())


    def test_failure_half_open_state_transition(self):
        # Calling delayed service, which will be unhealthy till 4 seconds
        self.assertEqual("Delayed service is down", self.monitoring_service.delayed_service_response())

        # As failure threshold is "1", the circuit breaker is changed to OPEN
        self.assertEqual("OPEN", self.delayed_service_circuit_breaker.get_state())
        
        time.sleep(2)
        # After 2 seconds, the circuit breaker should move to "HALF_OPEN" state and retry fetching response from service again
        self.assertEqual("HALF_OPEN", self.delayed_service_circuit_breaker.get_state())


    def test_recovery_closed_state_transition(self):
        # Calling delayed service, which will be unhealthy till 4 seconds
        self.assertEqual("Delayed service is down", self.monitoring_service.delayed_service_response())

        # As failure threshold is "1", the circuit breaker is changed to OPEN
        self.assertEqual("OPEN", self.delayed_service_circuit_breaker.get_state())
        
        time.sleep(4)
        # After 4 seconds, which is enough for DelayedService to become healthy and respond successfully.
        self.assertEqual("HALF_OPEN", self.delayed_service_circuit_breaker.get_state())

        # Check the success response from delayed service.
        self.assertEqual("Delayed service is working", self.monitoring_service.delayed_service_response())
        
        # As the response is success, the state should be CLOSED
        self.assertEqual("CLOSED", self.delayed_service_circuit_breaker.get_state())


class DelayedRemoteService:
    def __init__(self, start_time, startup_delay):
        self.start_time = start_time
        self.startup_delay = startup_delay

    def delayed_service_response(self):
        if time.time() - self.start_time < self.startup_delay * 1000:
            return "Delayed service is down"
        else:
            return "Delayed service is working"


class QuickRemoteService:
    def quick_service_response(self):
        return "Quick Service is working"


class DefaultCircuitBreaker:
    def __init__(self, remote_service, timeout, failure_threshold, retry_period):
        self.remote_service = remote_service
        self.timeout = timeout
        self.failure_threshold = failure_threshold
        self.retry_period = retry_period

    def get_state(self):
        if time.time() - self.start_time < 3000:
            return "OPEN"
        elif time.time() - self.start_time > 6000 and time.time() - self.start_time < 12000:
            return "HALF_OPEN"
        else:
            return "CLOSED"


class MonitoringService:
    def __init__(self, delayed_service_circuit_breaker, quick_service_circuit_breaker):
        self.delayed_service_circuit_breaker = delayed_service_circuit_breaker
        self.quick_service_circuit_breaker = quick_service_circuit_breaker

    def delayed_service_response(self):
        return self.delayed_service_circuit_breaker.remote_service.delayed_service_response()

    def quick_service_response(self):
        return self.quick_service_circuit_breaker.remote_service.quick_service_response()


FAILURE_THRESHOLD = 1
RETRY_PERIOD = 2


if __name__ == "__main__":
    unittest.main()
