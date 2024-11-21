Here is the translation of the Java code to Python:
```
import threading

class DataHeartbeatThread(threading.Thread):
    MAX_ELECTIONS_TO_SKIP = 5

    def __init__(self, data_group_member):
        super().__init__()
        self.data_group_member = data_group_member
        self.skipped_election_number = 0

    def send_heartbeat_sync(self, node):
        request = ...  # assume this is defined elsewhere
        request.set_header(data_group_member.get_header())
        super().send_heartbeat_sync(node)

    def send_heartbeat_async(self, node):
        request = ...  # assume this is defined elsewhere
        request.set_header(data_group_member.get_header())
        super().send_heartbeat_async(node)

    def start_election(self):
        if not self.data_group_member.this_node == self.data_group_member.header.node and \
           self.skipped_election_number < self.MAX_ELECTIONS_TO_SKIP and \
           not hasattr(self, 'has_had_leader'):
            self.skipped_election_number += 1
            return

        election_request = ...  # assume this is defined elsewhere
        election_request.set_header(data_group_member.get_header())

        super().start_election()
```
Note that I've assumed some variables and methods are defined elsewhere, as they were not provided in the original Java code. Specifically:

* `request` is used in `send_heartbeat_sync` and `send_heartbeat_async`, but its definition was omitted.
* `election_request` is used in `start_election`, but its definition was also omitted.
* `has_had_leader` is a boolean attribute that seems to be set by the thread, but its initialization was not provided.

You will need to define these variables and methods elsewhere in your Python code.