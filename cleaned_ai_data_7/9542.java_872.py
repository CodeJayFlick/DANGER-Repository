class CompositeFieldElement:
    def __init__(self, elements):
        self.field_elements = list(elements)
        if not all(isinstance(e, FieldElement) for e in self.field_elements):
            raise ValueError("All elements must be instances of FieldElement")

    @property
    def height_above(self):
        if self._height_above < 0:
            self._height_above = 0
            for field_element in self.field_elements:
                self._height_above = max(self._height_above, field_element.height_above)
        return self._height_above

    @property
    def height_below(self):
        if self._height_below < 0:
            self._height_below = 0
            for field_element in self.field_elements:
                self._height_below = max(self._height_below, field_element.height_below)
        return self._height_below

    def get_indexed_offset_for_char_position(self, char_position):
        n = 0
        for i in range(len(self.field_elements)):
            len_field_element = len(self.field_elements[i].text)
            if char_position < n + len_field_element:
                return IndexedOffset(i, char_position - n)
            n += len_field_element
        return IndexedOffset(len(self.field_elements) - 1,
                              len(self.field_elements[-1].text))

    def get_max_characters_for_width(self, width):
        remaining_width = width
        total_characters = 0
        for field_element in self.field_elements:
            next_width = field_element.string_width()
            if next_width >= remaining_width:
                total_characters += field_element.max_characters_for_width(remaining_width)
                break
            remaining_width -= next_width
            total_characters += len(field_element.text)
        return total_characters

    def get_color(self, index):
        pos = self.get_indexed_offset_for_char_position(index)
        return self.field_elements[pos.index].get_color(pos.offset)

    def char_at(self, index):
        pos = self.get_indexed_offset_for_char_position(index)
        return self.field_elements[pos.index].char_at(pos.offset)

    def replace_all(self, targets, replacement):
        new_strings = [field_element.replace_all(targets, replacement) for field_element in self.field_elements]
        return CompositeFieldElement(new_strings)

    def substring(self, start):
        return self.substring(start, len(self.text))

    def substring(self, start, end):
        pos_start = self.get_indexed_offset_for_char_position(start)
        pos_end = self.get_indexed_offset_for_char_position(end)

        if pos_start.index == pos_end.index:
            as_start = self.field_elements[pos_start.index]
            return as_start.substring(pos_start.offset, pos_end.offset)

        new_start = as_start.substring(pos_start.offset)
        as_end = self.field_elements[pos_end.index]
        new_end = as_end.substring(0, pos_end.offset)

        new_strings = [None] * (pos_end.index - pos_start.index + 1)
        for i in range(len(new_strings)):
            if i > 0:
                new_strings[i-1].text += self.field_elements[pos_start.index+i].text
        new_strings[0] = new_start
        new_strings[-1] = new_end

        return CompositeFieldElement(new_strings)

    def get_field_element(self, column):
        pos = self.get_indexed_offset_for_char_position(column)
        return self.field_elements[pos.index].get_field_element(pos.offset)

    @property
    def length(self):
        if not hasattr(self, '_length'):
            self._length = 0
            for field_element in self.field_elements:
                self._length += len(field_element.text)
        return self._length

    @property
    def text(self):
        if not hasattr(self, '_text'):
            buffer = ''
            for field_element in self.field_elements:
                buffer += field_element.text
            self._text = buffer
        return self._text

    def paint(self, c, g, x, y):
        xPos = x
        for field_element in self.field_elements:
            field_element.paint(c, g, xPos, y)
            xPos += field_element.string_width()

    @property
    def num_elements(self):
        return len(self.field_elements)

class IndexedOffset:
    def __init__(self, index, offset):
        self.index = index
        self.offset = offset

    def __str__(self):
        return f"IndexedOffset(index={self.index}, offset={self.offset})"

class FieldElement:
    pass  # You need to implement this class yourself
