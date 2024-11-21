import concurrent.futures
from io import StringIO


class IOResult:
    def __init__(self, inception=None):
        self.inception = inception
        self.consumer = None
        self.is_stream_opened = False

    def set_consumer(self, consumer):
        if not isinstance(consumer, callable):
            raise ValueError("Consumer must be a function")
        self.consumer = consumer


class ProcessConsumer:
    @staticmethod
    def consume(is_stream: StringIO, line_consumer=None) -> concurrent.futures.Future:
        is_stream.seek(0)

        def process_line(line):
            if line_consumer:
                line_consumer(line.strip())

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(process_line, is_stream.readline())
            while True:
                try:
                    line = is_stream.readline()
                    if not line:
                        break
                    process_line(line)
                except Exception as e:
                    future.set_exception(e)

        return future


def dummy_consumer(line):
    pass

# Example usage:

is_stream = StringIO("Hello\nWorld!\n")
future = ProcessConsumer.consume(is_stream, lambda x: print(x))
