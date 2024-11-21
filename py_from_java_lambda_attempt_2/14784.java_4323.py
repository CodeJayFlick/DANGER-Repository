Here is the translation of the Java code to Python:

```Python
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
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation, so I've simply defined the function as `test_message()` and called it at the end of the script.