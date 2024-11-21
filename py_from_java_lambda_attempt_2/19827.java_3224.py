Here is your Java code translated into Python:

```Python
class VariableString:
    def __init__(self, orig, string, mode):
        self.orig = orig
        self.string = list(string)
        self.mode = mode
        if not isinstance(self.string[0], str) and not all(isinstance(x, Expression) for x in self.string):
            raise ValueError("Invalid input")

    @staticmethod
    def newInstance(orig, mode=None):
        if mode is None:
            return VariableString(orig, [orig], StringMode.MESSAGE)
        else:
            try:
                s = orig.replace("\"\"", "%")
                string = []
                n = 0
                for i in range(len(s)):
                    c = s[i]
                    if c == '%':
                        n += -1 * (n > 0) or 1
                    elif not ((c == '}' and n < 0) or (c == '{' and n > 0)) and c != '"':
                        string.append(c)
                return VariableString(s, tuple(string), mode if isinstance(mode, StringMode) else None)
            except Exception as e:
                Skript.error(str(e))
                return None

    def to_string(self):
        s = ""
        for o in self.string:
            if isinstance(o, str):
                s += o
            elif isinstance(o, Expression):
                try:
                    s += Classes.toString(o.getArray(None), True, self.mode)
                except Exception as e:
                    Skript.error(str(e))
        return s

    def to_unformatted_string(self):
        s = ""
        for o in self.string:
            if isinstance(o, str):
                s += o
            elif isinstance(o, Expression):
                try:
                    s += Classes.toString(o.getArray(None), True, self.mode)
                except Exception as e:
                    Skript.error(str(e))
        return s

    def get_message_components(self, event=None):
        if not hasattr(event, 'get_array'):
            raise ValueError("Invalid input")
        message = []
        for o in self.string:
            if isinstance(o, str):
                message.append(ChatMessages.parse(o)[0])
            elif isinstance(o, Expression):
                try:
                    s = Classes.toString(o.getArray(None), True, self.mode)
                    ChatMessages.copy_styles(message[-1], ChatMessages.from_parsed_string(s))
                    return message
        return [ChatMessages.toJson(message)]

    def get_default_variable_name(self):
        if not hasattr(self, 'string'):
            raise ValueError("Invalid input")
        s = ""
        for o in self.string:
            if isinstance(o, str):
                s += o
            elif isinstance(o, Expression):
                try:
                    s += Classes.toString(o.get_array(None), True, self.mode)
                except Exception as e:
                    Skript.error(str(e))
        return s

    def set_mode(self, mode=None):
        if not hasattr(mode, 'get_string'):
            raise ValueError("Invalid input")
        if isinstance(mode, StringMode) or (self.is_simple()):
            return self
        else:
            try:
                vs = VariableString.newInstance(self.orig, tuple([mode]), None)
                Skript.error(str(e))
                return vs

    def get_single(self):
        return True