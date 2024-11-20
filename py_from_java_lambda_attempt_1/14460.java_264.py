Here is the translation of the Java code into Python:

```Python
class RingMessageManager:
    def __init__(self, instance_map):
        self.instance_map = instance_map

    def send_heartbeat_message(self, leader_id):
        leader_instance = self.instance_map.get(leader_id)
        return leader_instance.is_alive()

    def send_election_message(self, current_id, content):
        next_instance = self.find_next_instance(current_id)
        election_message = {"type": "ELECTION", "content": content}
        next_instance.on_message(election_message)
        return True

    def send_leader_message(self, current_id, leader_id):
        next_instance = self.find_next_instance(current_id)
        leader_message = {"type": "LEADER", "leader_id": str(leader_id)}
        next_instance.on_message(leader_message)
        return True

    def send_heartbeat_invoke_message(self, current_id):
        next_instance = self.find_next_instance(current_id)
        heartbeat_invoke_message = {"type": "HEARTBEAT_INVOKE", "content": ""}
        next_instance.on_message(heartbeat_invoke_message)

    def find_next_instance(self, current_id):
        # Implement this method to find the next instance
        pass

class Instance:
    def is_alive(self):
        # Implement this method to check if an instance is alive
        pass

    def on_message(self, message):
        # Implement this method for handling messages
        pass
```

Note that I have not implemented some methods (`find_next_instance`, `is_alive` and `on_message`) as they are specific to the context of your application. You would need to implement these based on how you want them to behave in your Python code.