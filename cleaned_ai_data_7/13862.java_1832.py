class CircuitBreaker:
    def __init__(self):
        self.state = "closed"

    # Success response. Reset everything to defaults
    def record_success(self):
        self.state = "open"
        print("Circuit breaker reset")

    # Failure response. Handle accordingly with response and change state if required.
    def record_failure(self, response: str) -> None:
        self.state = "half-open"
        print(f"Circuit breaker failed with {response}")

    # Get the current state of circuit breaker
    def get_state(self) -> str:
        return self.state

    # Set the specific state manually.
    def set_state(self, state: str) -> None:
        if state not in ["open", "half-open"]:
            raise ValueError("Invalid state")
        self.state = state

    # Attempt to fetch response from the remote service. 
    def attempt_request(self) -> str:
        try:
            return "response"
        except RemoteServiceException as e:
            print(f"Remote Service Exception: {e}")
