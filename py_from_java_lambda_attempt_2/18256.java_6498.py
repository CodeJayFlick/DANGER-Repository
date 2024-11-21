Here is the translation of the given Java code into Python:

```Python
import re

class Like:
    def __init__(self):
        pass

    @staticmethod
    def unescape_string(value: str) -> str:
        out = ""
        for ch in value:
            if ch == '\\':
                if i < len(value) - 1:
                    next_char = value[i + 1]
                    if next_char in ['%', '_', '\\']:
                        out += ch
                    elif next_char == '\\':
                        i += 1
                else:
                    out += ch
            else:
                out += ch
        return out

    def __init__(self, value: str, filter_type):
        self.value = value
        self.filter_type = filter_type
        try:
            unescaped_value = Like.unescape_string(value)
            special_regex_str = r'[^$*+?.{}[]|()'
            pattern_str_build = ''
            pattern_str_build += '^'
            for i, ch in enumerate(unescaped_value):
                if special_regex_str.find(str(ch)) != -1:
                    ch = '\\' + str(ch)
                elif (i == 0 or
                      i > 0 and '_' not in unescaped_value[i-1] or
                      i >= 2 and '%%' in pattern_str_build[-2:]):
                    replace_str = re.escape(ch).replace('%', r'.*?').replace('_', '.')
                    pattern_str_build += replace_str
                else:
                    pattern_str_build += ch
            pattern_str_build += '$'
            self.pattern = re.compile(pattern_str_build)

        except re.error as e:
            raise re.error("Regular expression error", value, e.start())

    def satisfy(self, statistics):
        return True

    def satisfy(self, time: int, value) -> bool:
        if self.filter_type != 'VALUE_FILTER':
            return False
        return bool(re.search(str(self.pattern), str(value)))

    def satisfy_start_end_time(self, start_time: int, end_time: int) -> bool:
        return True

    def contain_start_end_time(self, start_time: int, end_time: int) -> bool:
        return True

    def copy(self):
        return Like(self.value, self.filter_type)

    def serialize(self, output_stream):
        try:
            output_stream.write(str(self.get_serialize_id().ordinal()))
            output_stream.write(str(self.filter_type))
            ReadWriteIOUtils.write_object(self.value, output_stream)
        except Exception as ex:
            raise ValueError("Failed to serialize outputStream of type:", str(ex))

    def deserialize(self, buffer: bytes):
        self.filter_type = [value for value in FilterType][buffer[0]]
        self.value = ReadWriteIOUtils.read_string(buffer)

    def __str__(self) -> str:
        return f"{self.filter_type} is {self.value}"

    def get_serialize_id(self) -> int:
        return 1
```

Please note that this translation does not include the `FilterType` and `ReadWriteIOUtils` classes, as they are specific to Java.