class Message:
    def __init__(self, message):
        self.message = message

def test_message():
    # Parameterized constructor test.
    test_msg = "Message Test"
    msg = Message(test_msg)
    assert test_msg == msg.message

if __name__ == "__main__":
    test_message()
