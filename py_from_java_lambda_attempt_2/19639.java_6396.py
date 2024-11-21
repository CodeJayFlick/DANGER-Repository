Here is a translation of the Java code into equivalent Python:

```Python
class NowExpression:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Now"

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return """The current system time of the server. Use 'time' to get the Minecraft time of a world."""

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def examples(self):
        return ["broadcast \"Current server time: %now%\""]

    @examples.setter
    def examples(self, value):
        self._examples = value

    @property
    def since(self):
        return "1.4"

    @since.setter
    def since(self, value):
        self._since = value

def init(exprs, matched_pattern, is_delayed, parse_result):
    return True

class Date:
    pass

def get(event):
    return [Date()]

def is_single():
    return True

def get_return_type():
    return type(Date())

def to_string(event=None, debug=False):
    if event and debug:
        return "now"
    else:
        return str(get(event)[0])

# Register the expression
NowExpression().name = "now"

```

Please note that Python does not have direct equivalent of Java's `@Override`, `@Name`, `@Description`, etc. annotations, so I've used property decorators to simulate similar functionality.