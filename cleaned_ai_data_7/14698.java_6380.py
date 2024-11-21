import logging
from datetime import date

class Producer:
    def __init__(self, name: str, queue):
        self.name = name
        self.queue = queue
        self.is_stopped = False

    def send(self, body: str) -> None:
        if self.is_stopped:
            raise ValueError(f"Producer {self.name} was stopped and cannot deliver message [{body}]")
        msg = {"headers": {}, "body": body}
        msg["headers"]["DATE"] = str(date.today())
        msg["headers"]["SENDER"] = self.name
        try:
            self.queue.put(msg)
        except Exception as e:
            logging.error("Exception caught.", e)

    def stop(self) -> None:
        self.is_stopped = True
        try:
            self.queue.put({"POISON_PILL": "poison pill"})
        except Exception as e:
            logging.error("Exception caught.", e)


class MqPublishPoint:
    pass


# Example usage:
queue = MqPublishPoint()
producer = Producer("my_producer", queue)
producer.send("Hello, world!")
print(producer.is_stopped)  # False
producer.stop()
try:
    producer.send("This message will not be delivered")
except ValueError as e:
    print(e)  # "Producer my_producer was stopped and cannot deliver message [This message will not be delivered]"
