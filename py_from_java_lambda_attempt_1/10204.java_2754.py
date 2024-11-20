Here is your Java code translated into Python:

```Python
class JSONParser:
    def __init__(self):
        self.pos = 0
        self.toknext = 0
        self.toksuper = -1
        self.ndx = 0

    def allocate_token(self, tokens, type, start, end):
        token = {"type": type, "start": start, "end": end}
        tokens.append(token)
        return token

    def parse_primitive(self, js, tokens):
        start = self.pos
        found = False
        if not self.JSMN_STRICT:
            for i in range(len(js)):
                c = js[i]
                switcher = {
                    ',': None,
                    ']': None,
                    '}': None
                }
                if c in switcher:
                    found = True
                    break
                elif c < 32:
                    self.pos = start
                    return "JSMN_ERROR_INVAL"
            if not found:
                self.pos = start
                return "JSMN_ERROR_PART"
        for i in range(len(js)):
            c = js[i]
            switcher = {
                ',': None,
                ']': None,
                '}': None,
                '\t': None,
                '\r': None,
                '\n': None,
                ' ': None,
                ':': None
            }
            if c in switcher:
                found = True
                break
        self.allocate_token(tokens, "JSMN_PRIMITIVE", start + 1, i)
        return "JSMN_SUCCESS"

    def parse_string(self, js):
        start = self.pos
        for i in range(len(js)):
            if js[i] == '"':
                token = {"type": "JSMN_STRING", "start": start + 1, "end": i}
                tokens.append(token)
                return "JSMN_SUCCESS"
            elif js[i] == '\\':
                self.pos += 2
        self.pos = start
        return "JSMN_ERROR_PART"

    def parse(self, js):
        r = None
        for c in js:
            switcher = {
                '{': {"type": "JSMN_OBJECT", "start": self.pos},
                '[': {"type": "JSMN_ARRAY", "start": self.pos}
            }
            if c in switcher:
                token = switcher[c]
                while True:
                    for i in range(len(js)):
                        d = js[i]
                        if d == '}':
                            token["end"] = i
                            break
                        elif d == ']':
                            token["end"] = i
                            break
                    self.pos += 1
            elif c == '"':
                r = self.parse_string(js)
        return "JSMN_SUCCESS"

    def convert(self, s):
        if not hasattr(self, 'ndx'):
            self.ndx = 0
        tp = tokens[self.ndx]
        tstr = "".join(s[tp["start"]:tp["end"]])
        switcher = {
            "JSMN_OBJECT": {"case": lambda: self.convert_object(tstr)},
            "JSMN_ARRAY": {"case": lambda: self.convert_array(tstr)}
        }
        if tp["type"] in switcher:
            return switcher[tp["type"]]["case"]()
        elif tp["type"] == "JSMN_PRIMITIVE":
            i = s.index(tp["start"])
            c = s[i]
            switcher = {
                't': {"return": True},
                'f': {"return": False},
                'n': {"return": None}
            }
            if c in switcher:
                return switcher[c]["return"]
        elif tp["type"] == "JSMN_STRING":
            return tstr
        else:
            raise Exception("Invalid JSON type")

    def convert_object(self, s):
        tab = {}
        for i in range(0, len(s), 2):
            k = self.convert(s[i:])
            v = self.convert(s[i+1:])
            tab[k] = v
        return tab

    def convert_array(self, s):
        l = []
        while True:
            obj = self.convert(s)
            if isinstance(obj, dict) or isinstance(obj, list):
                break
            else:
                l.append(obj)
        return l


class JSONToken:
    pass


def isxdigit(b):
    switcher = {
        '0': None,
        '1': None,
        '2': None,
        '3': None,
        '4': None,
        '5': None,
        '6': None,
        '7': None,
        '8': None,
        '9': None,
        'A': None,
        'B': None,
        'C': None,
        'D': None,
        'E': None,
        'F': None,
        'a': None,
        'b': None,
        'c': None,
        'd': None,
        'e': None,
        'f': None
    }
    if b in switcher:
        return True
    else:
        return False


# Example usage:

js = '{"name": "John", "age": 30, "city": "New York"}'
tokens = []
parser = JSONParser()
r = parser.parse(js)
if r == "JSMN_SUCCESS":
    for obj in parser.convert(js):
        print(obj)

```

Please note that this code does not handle all edge cases and is meant to be a basic translation of the Java code.