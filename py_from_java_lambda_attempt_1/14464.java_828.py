Here is the translation of the Java code to Python:
```
import unittest

class MessageTest(unittest.TestCase):
    def test_get_type(self):
        message = Message(MessageType.HEARTBEAT, "")
        self.assertEqual(message.type, MessageType.HEARTBEAT)

    def test_get_content(self):
        content = "test"
        message = Message(MessageType.HEARTBEAT, content)
        self.assertEqual(message.content, content)


class Message:
    def __init__(self, type: str, content: str):
        self.type = type
        self.content = content


if __name__ == '__main__':
    unittest.main()
```
Note that I had to make some assumptions about the `Message` class and its attributes, as they were not provided in the original Java code. In particular:

* The `MessageType` enum is assumed to be a string (e.g., "HEARTBEAT") rather than an actual enum.
* The `Message` class has two attributes: `type` and `content`, which are initialized with the values passed to its constructor.

Please let me know if these assumptions are incorrect or if you'd like me to revise anything!