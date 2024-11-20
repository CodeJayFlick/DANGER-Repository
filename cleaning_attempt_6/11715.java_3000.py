class SubExpression:
    def __init__(self, location):
        super().__init__(location)

    def __init__(self, location, l, r):
        super().__init__(location, l, r)

    def get_value(self, pos):
        left_val = self.get_left().get_value(pos)
        right_val = self.get_right().get_value(pos)
        return left_val - right_val

    def get_sub_value(self, replace, list_pos):
        left_val = self.get_left().get_sub_value(replace, list_pos)  # Must be left first
        right_val = self.get_right().get_sub_value(replace, list_pos)
        return left_val - right_val

    def save_xml(self, s):
        s.write("<sub_exp>\n")
        super().save_xml(s)
        s.write("</sub_exp>\n")

# Note: Python does not have direct equivalent of Java's VectorSTL and MutableInt.
