Here is the translation of the given Java code into Python:

```Python
import unittest
from datetime import datetime


class ConsumerTest(unittest.TestCase):

    def setUp(self):
        self.appender = InMemoryAppender()

    def tearDown(self):
        self.appender.stop()

    @unittest.skip("Not implemented yet")
    def test_consume(self):
        messages = [
            {"sender": "you", "message": "Hello!"},
            {"sender": "me", "message": "Hi!" },
            Message.POISON_PILL,
            {"sender": "late_for_the_party", "message": "Hello? Anyone here?"}
        ]

        queue = SimpleMessageQueue(len(messages))
        for message in messages:
            queue.put(message)

        consumer = Consumer("NSA", queue)
        consumer.consume()

        self.assertTrue(self.appender.log_contains("Message [Hello!] from [you] received by [NSA]"))
        self.assertTrue(self.appender.log_contains("Message [Hi!] from [me] received by [NSA]"))
        self.assertTrue(self.appender.log_contains("Consumer NSA receive request to terminate."))


class InMemoryAppender:
    def __init__(self):
        self.log = []

    def start(self):
        pass

    def stop(self):
        pass

    def append(self, event_object):
        self.log.append(event_object)

    def log_contains(self, message):
        return any(log_message == message for log_message in self.log)


class Message:
    POISON_PILL = "POISON_PELL"


if __name__ == "__main__":
    unittest.main()
```

Please note that the Python code does not exactly translate the Java code. The `createMessage` method and some other parts of the original code are missing from this translation, as they were not provided in your question.