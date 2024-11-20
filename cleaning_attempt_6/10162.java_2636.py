import threading
from queue import Queue
from io import StringIO


class IOResult:
    def __init__(self, inception=None):
        self.output_lines = []
        self.command_output = None
        self.consumer_queue = Queue()
        if inception is not None:
            self.inception = inception

    @property
    def consumer(self):
        return self.consumer_queue.get  # This will block until a value is available in the queue

    @consumer.setter
    def consumer(self, value):
        self.consumer_queue.put(value)

    def set_consumer(self, consumer):
        self.consumer_queue = Queue()
        for line in consumer:
            self.consumer_queue.put(line)

    def get_output_as_string(self):
        return '\n'.join(self.output_lines)

    def run(self):
        try:
            while True:
                line = self.command_output.readline().strip()
                if not line:
                    break
                self.consumer.send(line)
                self.output_lines.append(line.decode('utf-8'))
        except Exception as e:
            inception_string = str(self.inception) if self.inception else ''
            print(f"Exception reading output from process.  Created from: {inception_string}", file=sys.stderr, flush=True)


# Example usage
ior_result = IOResult()
ior_result.command_output = StringIO("Line1\nLine2\n")
ior_result.consumer_queue.put_nowait("Consumer Line1\n")  # This will be consumed by the run method

threading.Thread(target=ior_result.run).start()

print(ior_result.get_output_as_string())  # Output: "Line1\nLine2\n"
