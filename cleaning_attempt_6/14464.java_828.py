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
