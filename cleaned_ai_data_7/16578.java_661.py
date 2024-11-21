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
