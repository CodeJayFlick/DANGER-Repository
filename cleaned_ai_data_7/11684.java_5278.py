class BinaryExpression:
    def __init__(self, location):
        self.left = None
        self.right = None
        super().__init__(location)

    @property
    def left(self):
        return self._left

    @left.setter
    def left(self, value):
        if not isinstance(value, PatternExpression):
            raise ValueError("Left must be a PatternExpression")
        self._left = value

    @property
    def right(self):
        return self._right

    @right.setter
    def right(self, value):
        if not isinstance(value, PatternExpression):
            raise ValueError("Right must be a PatternExpression")
        self._right = value

    def gen_min_pattern(self, ops):
        # This method is equivalent to the Java method. However,
        # it's unclear what this method should do in Python.
        pass

    def list_values(self, list):
        if self.left:
            self.left.list_values(list)
        if self.right:
            self.right.list_values(list)

    def get_min_max(self, minlist, maxlist):
        if self.left:
            self.left.get_min_max(minlist, maxlist)
        if self.right:
            self.right.get_min_max(minlist, maxlist)

    def __init__(self, location, l, r):
        super().__init__(location)
        self.left = l
        self.right = r

    def dispose(self):
        if self.left is not None:
            PatternExpression.release(self.left)
        if self.right is not None:
            PatternExpression.release(self.right)

    def save_xml(self, s):
        if self.left:
            self.left.save_xml(s)
        if self.right:
            self.right.save_xml(s)

    def restore_xml(self, el, trans):
        list = el.getChildren()
        self.left = PatternExpression.restore_expression(list[0], trans)
        self.right = PatternExpression.restore_expression(list[1], trans)
