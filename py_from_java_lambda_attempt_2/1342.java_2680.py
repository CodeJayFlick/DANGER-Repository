Here is a translation of the provided Java code into equivalent Python:

```Python
import re

class GdbEvaluateCommand:
    MI2_CMD = "-data-evaluate-expression"
    MAX_EXPR_LEN = 999 - len(MI2_CMD) - 6

    def __init__(self, manager, thread_id, frame_id, expression):
        self.manager = manager
        self.thread_id = thread_id
        self.frame_id = frame_id
        self.expression = expression

    def encode(self, thread_part, frame_part):
        return f"{MI2_CMD}{thread_part}{frame_part} {f'\"{self.escape_expression(self.expression)}\'}"

    @staticmethod
    def escape_expression(expression):
        import re
        pattern = r"([.*+?^${()|[\]\\\/])"
        escaped_expr = re.sub(pattern, lambda x: f"\\{x.group(0)}", expression)
        return escaped_expr

    def complete(self, pending_command):
        if isinstance(pending_command, GdbCommandDoneEvent):
            return pending_command.assume_value()
```

Please note that Python does not have direct equivalent of Java's `StringEscapeUtils.escapeJava()` method as it is a part of Apache Commons Text library which provides utility classes for working with strings and other text data.