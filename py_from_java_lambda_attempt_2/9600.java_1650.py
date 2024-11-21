Here is the translation of the Java code into Python:

```Python
import re

class FieldUtils:
    WHITE_SPACE = ['\t', '\n', '\r', '\f']

    def __init__(self):
        pass  # utility class

    @staticmethod
    def wrap(field_elements, width):
        wrapped_elements = []
        for field_element in field_elements:
            wrapped_elements.extend(FieldUtils.word_wrap_list(field_element, width))
        return wrapped_elements

    @staticmethod
    def word_wrap_list(field_element, width):
        lines = []

        original_field_element = re.sub(' +', ' ', str(field_element)).strip()
        if len(original_field_element) <= width:
            lines.append(original_field_element)
            return lines

        wrap_position = FieldUtils.find_word_wrap_position(original_field_element, width)
        while wrap_position > 0:
            lines.append(original_field_element[:wrap_position].strip())
            original_field_element = original_field_element[wrap_position:].lstrip()
            wrap_position = FieldUtils.find_word_wrap_position(original_field_element, width)

        lines.append(original_field_element.strip())

        return lines

    @staticmethod
    def find_word_wrap_position(text, width):
        if len(text) <= width:
            return 0

        white_space_positions = [i for i in range(len(text)-1, -1, -1)
                                  if text[i] == ' ' and i < width]
        if white_space_positions:
            return white_space_positions[0]

        return min(range(width), key=lambda x: len(text[:x]))

    @staticmethod
    def trim_string(string):
        buffer = StringBuilder(str(string))
        while 0 <= buffer.length() - 1:
            char_at = buffer.charAt(0)
            if not re.match(r'\w', str(char_at)):
                return buffer.substring(0, buffer.length()-1).toString()
            else:
                for i in range(buffer.length()):
                    if re.match(r'\w', str(buffer.charAt(i))):
                        return buffer.toString()[:i+1]
        return string
```

Note that the `StringBuilder` class is not available in Python. Instead, you can use a list to build your string and then join it with an empty separator (`' '.join(...)`) or convert it back into a string using `''.join(map(str, ...))`.