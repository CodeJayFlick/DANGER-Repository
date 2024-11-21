class BinaryExpression:
    def __init__(self):
        self.left = None
        self.right = None

    def hash(self):
        result = 0
        if self.left is not None:
            result += hash(self.left)
        else:
            result += 0
        result *= 31
        result += hash(type(self))
        if self.right is not None:
            result += hash(self.right)
        return result

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        elif isinstance(other, BinaryExpression):
            if self.left != other.left or self.right != other.right:
                return False
            else:
                return True
        else:
            return False

    @property
    def left(self):
        return self._left

    @left.setter
    def left(self, value):
        self._left = value

    @property
    def right(self):
        return self._right

    @right.setter
    def right(self, value):
        self._right = value

    def restore_xml(self, parser, lang):
        el = parser.start()
        if 'left' in parser:
            self.left = PatternExpression.restore_expression(parser, lang)
        else:
            self.left = None
        if 'right' in parser:
            self.right = PatternExpression.restore_expression(parser, lang)
        else:
            self.right = None
        parser.end(el)

class PatternExpression:
    def restore_expression(self, parser, lang):
        # implement this method based on the actual implementation of PatternExpression class
        pass

