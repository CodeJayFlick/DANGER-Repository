import re

class IntegerFormatter:
    def __init__(self):
        self.my_document_filter = None
        number_format = NumberFormat.getIntegerInstance()
        number_format.setGroupingUsed(False)
        number_format.setParseIntegerOnly(True)
        self.set_format(number_format)
        self.set_value_class(int)

        # this lets spaces in (we control other characters below in is_valid_text())
        self.set_allows_invalid(True)

    def get_document_filter(self):
        if not self.my_document_filter:
            self.my_document_filter = self.create_document_filter()
        return self.my_document_filter

    def create_document_filter(self):
        return PositiveValueIntegerDocumentFilterWrapper(self.get_format(), super().get_document_filter())

    def get_original_document_filter(self):
        return super().get_document_filter()

class PositiveValueIntegerDocumentFilterWrapper:
    def __init__(self, format, wrapped_filter):
        self.format = format
        self.wrapped_filter = wrapped_filter

    def remove(self, fb, offset, length):
        document = fb.get_document()
        text = document.get_text(0, document.get_length())
        buildy = StringBuilder(text)
        buildy.delete(offset, offset + length)

        if not is_valid_text(buildy.toString()):
            warn()
            return

        self.wrapped_filter.remove(fb, offset, length)

    def insert_string(self, fb, offset, string):
        document = fb.get_document()
        text = document.get_text(0, document.get_length())
        buildy = StringBuilder(text)
        buildy.insert(offset, string)

        if not is_valid_text(buildy.toString()):
            warn()
            return

        self.wrapped_filter.insert_string(fb, offset, string)

    def replace(self, fb, offset, length, text):
        document = fb.get_document()
        text = document.get_text(0, document.get_length())
        buildy = StringBuilder(text)
        buildy.replace(offset, offset + length, text)

        if not is_valid_text(buildy.toString()):
            warn()
            return

        self.wrapped_filter.replace(fb, offset, length, text)

    def is_valid_text(self, text):
        if '-' in text:
            return False
        if text == '':
            return True
        if re.search(r'\D', text):
            return False
        number = parse_text(text)
        if not isinstance(number, int) or number < 0:
            return False
        return True

    def contains_non_numeric_characters(self, text):
        for char in text:
            if not is_digit(char):
                return True
        return False

    def is_digit(self, character):
        return re.match(r'\d', str(character))

    def parse_text(self, text):
        try:
            number = self.format.parse_object(text)
            if not isinstance(number, int):
                return None
            return number
        except (ValueError, TypeError):
            return None

    def warn(self):
        import os
        print('\a', file=os.fdopen(0, 'w'))

if __name__ == "__main__":
    formatter = IntegerFormatter()
