import logging
from threading import Lock, Condition
from typing import List

class AppendGroupEntryHandler:
    def __init__(self,
                 group_received_counter: List[int],
                 receiver_node_index: int,
                 receiver_node: object,
                 leader_ship_stale: bool,
                 log: object,
                 new_leader_term: int,
                 member: object):
        self.logger = logging.getLogger(__name__)
        self.group_received_counter = group_received_counter
        self.receiver_node_index = receiver_node_index
        self.receiver_node = receiver_node
        self.leader_ship_stale = leader_ship_stale
        self.log = log
        self.new_leader_term = new_leader_term
        self.member = member

    def on_complete(self, response: int):
        if self.leader_ship_stale:
            return

        if response == 1:  # RESPONSE_AGREE
            self.process_agreement()
        elif response > 0:
            with Lock():
                previous_new_term = self.new_leader_term
                if previous_new_term < response:
                    self.new_leader_term = response
                else:
                    self.leader_ship_stale = True

    def process_agreement(self):
        with Lock():
            self.logger.debug(f"{self.member} has accepted log {self.log}")
            for i in range(len(self.group_received_counter)):
                node_index = (self.receiver_node_index - i) % len(self.group_received_counter)
                if self.group_received_counter[node_index] > 0:
                    self.group_received_counter[node_index] -= 1

        all_agreed = True
        for remaining in self.group_received_counter:
            if remaining > 0:
                all_agreed = False
                break

        if all_agreed:
            with Lock():
                self.logger.debug(f"{self.member} has agreed")
                self.group_received_counter.notify_all()

    def on_error(self, exception: Exception):
        self.logger.error(f"{self.member}: Cannot send the add node request to {self.receiver_node}", exception)
        errored_nodes = 0
        while True:
            if errored_nodes >= len(self.group_received_counter) / 2:
                with Lock():
                    self.logger.error(f"{self.member}: Over half of the nodes failed, the request is rejected")
                    self.group_received_counter.notify_all()
                break
            errored_nodes += 1

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
