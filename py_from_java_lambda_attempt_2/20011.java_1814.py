Here is the translation of the Java code into Python:

```Python
import re

class StringUtils:
    @staticmethod
    def check_indices(s, start, end):
        if start < 0 or end > len(s):
            raise StringIndexOutOfBoundsException("invalid start/end indices " + str(start) + "," + str(end) + " for string '" + s + "' (length " + str(len(s)) + ")")

    @staticmethod
    def fancy_order_number(i):
        i_mod_ten = i % 10
        i_mod_hundred = i % 100
        if i_mod_ten == 1 and i_mod_hundred != 11:
            return str(i) + 'st'
        elif i_mod_ten == 2 and i_mod_hundred != 12:
            return str(i) + 'nd'
        elif i_mod_ten == 3 and i_mod_hundred != 13:
            return str(i) + 'rd'
        else:
            return str(i) + 'th'

    @staticmethod
    def replace_all(string, regex, callback):
        matcher = re.compile(regex).matcher(string)
        buffer = StringBuffer()
        while matcher.find():
            replacement = callback(matcher.group())
            if replacement is None:
                return None
            matcher.appendReplacement(buffer, replacement)
        matcher.appendTail(buffer)
        return buffer.toString()

    @staticmethod
    def count(s, c):
        return count(s, c, 0, len(s))

    @staticmethod
    def count(s, c, start):
        return count(s, c, start, len(s))

    @staticmethod
    def count(s, c, start, end):
        StringUtils.check_indices(s, start, end)
        result = 0
        for i in range(start, end):
            if s[i] == c:
                result += 1
        return result

    @staticmethod
    def contains(s, c, start=0, end=len(s)):
        StringUtils.check_indices(s, start, end)
        for i in range(start, end):
            if s[i] == c:
                return True
        return False

    @staticmethod
    def to_string(d, accuracy):
        assert accuracy >= 0
        if accuracy <= 0:
            return str(round(d))
        string = format(Locale.US, "%." + str(accuracy) + "f", d)
        i = len(string) - 1
        while string[i] == '0':
            i -= 1
        if string[i] == '.':
            i -= 1
        return string[:i+1]

    @staticmethod
    def first_upper(s):
        if not s:
            return s
        if Character.isUpperCase(s[0]):
            return s
        return Character.toUpperCase(s[0]) + s[1:]

    @staticmethod
    def substring(s, start, end):
        if start < 0:
            start = len(s) + start
        if end < 0:
            end = len(s) + end
        if end < start:
            raise ValueError("invalid indices")
        return s[start:end]

    @staticmethod
    def fix_capitalization(string):
        chars = list(string)
        i = 0
        while True:
            c = chars[i]
            if '0' <= c <= '9':
                break
            elif c == '.' or c in ['!', '?']:
                break
            else:
                i += 1
        return ''.join(chars[:i+1] + [c.upper() for c in chars[i:]])

    @staticmethod
    def number_after(s, index):
        return StringUtils.number_at(s, index, True)

    @staticmethod
    def number_before(s, index):
        return StringUtils.number_at(s, index, False)

    @staticmethod
    def number_at(s, index, forward=True):
        if not s:
            raise ValueError("empty string")
        assert 0 <= index < len(s), "index out of bounds"
        i = index
        d1 = -1
        has_dot = False
        while True:
            c = s[i]
            if '0' <= c <= '9':
                if d1 == -1:
                    d1, d2 = i, i
                else:
                    d1 += 1 * (forward and 1 or -1)
            elif c == '.':
                has_dot = True
                if d1 == -1:
                    d1, d2 = i, i
                else:
                    d1 += 1 * (forward and 1 or -1)
            elif Character.isWhitespace(c):
                break
            elif not forward and s[i] in ['.', '!', '?']:
                return float(s[d1+1:])
            i += 1 * (forward and 1 or -1)
        if d1 == -1:
            return -1.0
        return float(s[d1:d2+1])

    @staticmethod
    def starts_with_ignore_case(string, start):
        return StringUtils.starts_with_ignore_case(string, start, 0)

    @staticmethod
    def starts_with_ignore_case(string, start, offset=0):
        if not string:
            raise ValueError("empty string")
        assert 0 <= offset < len(string), "offset out of bounds"
        if offset >= len(start) or offset == len(string):
            return False
        return string[offset:offset+len(start)].lower() == start.lower()

    @staticmethod
    def ends_with_ignore_case(s, end):
        if not s:
            raise ValueError("empty string")
        assert 0 <= len(end), "end out of bounds"
        if offset >= len(s) - len(end) or offset == len(s):
            return False
        return s[offset:offset+len(end)].lower() == end.lower()

    @staticmethod
    def multiply(s, amount=1):
        if not s:
            return ""
        if amount <= 0:
            return ""
        elif amount == 1:
            return s
        else:
            chars = list(s)
            result = [''] * len(chars) * amount
            for i in range(len(result)):
                j = i // len(chars)
                k = i % len(chars)
                if j < amount - 1 or k >= len(chars):
                    break
                result[i] = chars[k]
            return ''.join(result)

    @staticmethod
    def join(strings, delimiter=""):
        if not strings:
            return ""
        buffer = StringBuffer()
        for s in strings:
            buffer.append(s)
            buffer.append(delimiter)
        return buffer.toString()

    @staticmethod
    def replace(string, needle, replacement):
        return string.replace(needle, replacement)

    @staticmethod
    def replace_first(string, needle, replacement):
        return re.sub(re.escape(needle), replacement, string, count=1)

    @staticmethod
    def hex_string_to_byte_array(s):
        len_s = len(s)
        data = [0] * (len_s // 2)
        for i in range(len_s):
            if i % 2 == 0:
                j = i // 2
                data[j] = int(s[i:i+2], 16) << 4
            else:
                j = i // 2
                data[j] += ord(s[i])
        return bytes(data)

    @staticmethod
    def index_of_outside_group(string, find, group_open, group_close):
        group = 0
        for i in range(len(string)):
            c = string[i]
            if c == '\\':
                i += 1
            elif c == group_open:
                group += 1
            elif c == group_close:
                group -= 1
            elif c == find and group == 0:
                return i
        return -1

```

Note that Python does not have a direct equivalent to Java's `StringIndexOutOfBoundsException`. Instead, you can raise a custom exception or use the built-in `ValueError` class.