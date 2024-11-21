Here is the translation of the Java code to Python:
```
import logging

class XmlMessageLog(logging.Logger):
    def __init__(self):
        super().__init__()

    def set_parser(self, parser):
        self.parser = parser

    @logging.Logger.appendMsg
    def append_msg(self, msg: str) -> None:
        line_num = 0
        if self.parser is not None:
            line_num = self.parser.get_line_number()
        if line_num > 0:
            self.log(line_num, msg)
        else:
            super().log(msg)

class XmlPullParser:
    def get_line_number(self):
        # implement this method to return the current line number
        pass

# Example usage:
parser = XmlPullParser()  # assume you have implemented this class
message_log = XmlMessageLog()
message_log.set_parser(parser)
message_log.append_msg("This is a test message")
```
Note that I had to make some assumptions about how `XmlPullParser` would work, since the original Java code didn't provide any implementation for it. You'll need to implement the `get_line_number()` method in your Python equivalent of this class.

Also, I used the built-in `logging` module in Python to create a logger that can be used with the `append_msg()` method. This is similar to how you would use Java's `MessageLog` class.