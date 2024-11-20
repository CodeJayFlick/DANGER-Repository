import logging
from queue import Queue
from threading import Thread

class AbstractInstance:
    HEARTBEAT_INTERVAL = 5000
    INSTANCE = "Instance"

    def __init__(self, message_manager: 'MessageManager', local_id: int, leader_id: int):
        self.message_manager = message_manager
        self.message_queue = Queue()
        self.local_id = local_id
        self.leader_id = leader_id
        self.alive = True

    def run(self) -> None:
        while True:
            if not self.message_queue.empty():
                self.process_message(self.message_queue.get())

    def on_message(self, message: 'Message') -> None:
        self.message_queue.put(message)

    def is_alive(self) -> bool:
        return self.alive

    def set_alive(self, alive: bool) -> None:
        self.alive = alive

    def process_message(self, message: 'Message') -> None:
        if message.type == "ELECTION":
            logging.info(f"{self.INSTANCE} {self.local_id} - Election Message handling...")
            self.handle_election_message(message)
        elif message.type == "LEADER":
            logging.info(f"{self.INSTANCE} {self.local_id} - Leader Message handling...")
            self.handle_leader_message(message)
        elif message.type == "HEARTBEAT":
            logging.info(f"{self.INSTANCE} {self.local_id} - Heartbeat Message handling...")
            self.handle_heartbeat_message(message)

    def handle_election_message(self, message: 'Message') -> None:
        pass

    def handle_leader_message(self, message: 'Message') -> None:
        pass

    def handle_heartbeat_message(self, message: 'Message') -> None:
        pass


class MessageManager:

    # Your code here
