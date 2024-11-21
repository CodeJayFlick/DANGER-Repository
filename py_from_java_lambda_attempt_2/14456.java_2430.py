Here is the translation of the Java interface into a Python class:

```Python
class MessageManager:
    def __init__(self):
        pass

    def send_heartbeat_message(self, leader_id: int) -> bool:
        # Implement your logic here to check whether the leader instance is alive.
        return True  # Replace with actual implementation.

    def send_election_message(self, current_id: int, content: str) -> bool:
        # Implement your logic here for sending election message and checking its acceptance by target instances.
        return True  # Replace with actual implementation.

    def send_leader_message(self, current_id: int, leader_id: int) -> bool:
        # Implement your logic here for sending new leader notification message and checking its acceptance by target instances.
        return True  # Replace with actual implementation.

    def send_heartbeat_invoke_message(self, current_id: int):
        # Implement your logic here to invoke heartbeat task in the target instance.
        pass
```

Please note that this is a direct translation of Java interface into Python class. You will need to implement the actual functionality for each method based on your specific requirements and use cases.