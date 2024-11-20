class ArrayElementWrappedOption:
    SHOW_MULTI_ELEMENTS_PER_LINE = "showMultiArrayElementsPerLine"
    ELEMENTS_PER_LINE = "elementsPerLine"
    DEFAULT_SHOW_MULTI = True
    DEFAULT_ELEMENTS_PER_LINE = 4

    def __init__(self):
        self.show_multiple_array_element_per_line = DEFAULT_SHOW_MULTI
        self.array_elements_per_line = DEFAULT_ELEMENTS_PER_LINE

    def equals(self, obj):
        if not isinstance(obj, ArrayElementWrappedOption):
            return False
        if self is obj:
            return True
        other_option = obj
        return (self.show_multiple_array_element_per_line == 
                other_option.show_multiple_array_element_per_line) and \
               (self.array_elements_per_line == other_option.array_elements_per_line)

    def __hash__(self):
        prime = 31
        result = 1
        result = prime * result + int(self.show_multiple_array_element_per_line)
        result = prime * result + self.array_elements_per_line
        return result

    # Persistence
    def read_state(self, save_state):
        if SHOW_MULTI_ELEMENTS_PER_LINE in save_state:
            self.show_multiple_array_element_per_line = \
                save_state[SHOW_MULTI_ELEMENTS_PER_LINE]
        else:
            self.show_multiple_array_element_per_line = DEFAULT_SHOW_MULTI
        if ELEMENTS_PER_LINE in save_state:
            self.array_elements_per_line = save_state[ELEMENTS_PER_LINE]
        else:
            self.array_elements_per_line = DEFAULT_ELEMENTS_PER_LINE

    def write_state(self, save_state):
        save_state[SHOW_MULTI_ELEMENTS_PER_LINE] = \
            self.show_multiple_array_element_per_line
        save_state[ELEMENTS_PER_LINE] = self.array_elements_per_line

    @property
    def show_multiple_array_element_per_line(self):
        return self.show_multiple_array_element_per_line

    @show_multiple_array_element_per_line.setter
    def show_multiple_array_element_per_line(self, b):
        if not isinstance(b, bool):
            raise TypeError("Boolean expected")
        self.show_multiple_array_element_per_line = b

    @property
    def array_elements_per_line(self):
        return self.array_elements_per_line

    @array_elements_per_line.setter
    def array_elements_per_line(self, value):
        if value <= 0:
            value = 1
        self.array_elements_per_line = value
