import re


class BoundedRangeDecimalFormatter:
    def __init__(self, upper_range_value, lower_range_value, number_format):
        self.upper_range_value = upper_range_value
        self.lower_range_value = lower_range_value
        self.number_format = number_format

    def get_document_filter(self):
        if not hasattr(self, 'my_document_filter'):
            my_document_filter = BoundedRangeDocumentFilterWrapper(super().get_document_filter())
            setattr(self, 'my_document_filter', my_document_filter)
        return getattr(self, 'my_document_filter')

    class BoundedRangeDocumentFilterWrapper:
        def __init__(self, wrapped_filter):
            self.wrapped_filter = wrapped_filter

        def remove(self, fb, offset, length):
            text = fb.get_text(0, fb.get_length())
            buildy = re.sub(r'(\d+)(\.?\d*)', lambda m: f'{m.group(1)}{self.number_format.format(float(m.group(2)) if m.group(2) else 0).replace('.', '')}', text)
            if not self.is_valid_text(buildy):
                warn()
                return
            self.wrapped_filter.remove(fb, offset, length)

        def insert_string(self, fb, offset, string, attr):
            text = fb.get_text(0, fb.get_length())
            buildy = re.sub(r'(\d+)(\.?\d*)', lambda m: f'{m.group(1)}{self.number_format.format(float(m.group(2)) if m.group(2) else 0).replace('.', '')}', text)
            buildy.insert(offset, string)
            if not self.is_valid_text(buildy):
                warn()
                return
            self.wrapped_filter.insert_string(fb, offset, string, attr)

        def replace(self, fb, offset, length, text, attr):
            original_text = fb.get_text(0, fb.get_length())
            buildy = re.sub(r'(\d+)(\.?\d*)', lambda m: f'{m.group(1)}{self.number_format.format(float(m.group(2)) if m.group(2) else 0).replace('.', '')}', original_text)
            buildy.replace(offset, offset + length, text)
            if not self.is_valid_text(buildy):
                warn()
                return
            self.wrapped_filter.replace(fb, offset, length, text, attr)

        def is_valid_text(self, text):
            if '.' == text or '' == text:
                return True  # special case, let the decimal through

            if '-' == text and self.lower_range_value < 0:
                return True  # another special case; let the ' -' through if it's the first character (user is entering a negative number). But only allow this if the lower bound is negative.

            if not re.match(r'^-?\d+(\.\d+)?$', text):
                return False

            try:
                float(text)
                value = float(text)
                if value > self.upper_range_value or value < self.lower_range_value:
                    return False  # no negatives or values over 1
                return True
            except ValueError:
                return False

        def contains_non_numeric_characters(self, text):
            for char in text:
                if not re.match(r'^-?\d+(\.\d+)?$', str(char)):
                    return True
            return False

        def is_negative(self, i, the_char):
            if i != 0:
                return False  # '-' is only allowed as the first character
            return the_char == '-'

        def warn(self):
            import os
            os.system('beep')

# Example usage:

formatter = BoundedRangeDecimalFormatter(10.0, -5.0, '#,###')
