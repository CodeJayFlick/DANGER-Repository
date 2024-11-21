class BinaryExpression:
    def __init__(self):
        pass

def and_(left: 'IExpression', right: 'IExpression') -> 'AndExpression':
    return AndExpression(left, right)

def or_(left: 'IExpression', right: 'IExpression') -> 'OrExpression':
    return OrExpression(left, right)


class IExpression:
    def __init__(self):
        pass


class IBinaryExpression(IExpression):
    def clone(self) -> 'IBinaryExpression':
        raise NotImplementedError

    @property
    def left(self) -> 'IExpression':
        raise NotImplementedError

    @left.setter
    def left(self, value: 'IExpression'):
        raise NotImplementedError

    @property
    def right(self) -> 'IExpression':
        raise NotImplementedError

    @right.setter
    def right(self, value: 'IExpression'):
        raise NotImplementedError


class AndExpression(BinaryExpression):
    def __init__(self, left: 'IExpression', right: 'IExpression'):
        self.left = left
        self.right = right

    @property
    def left(self) -> 'IExpression':
        return self._left

    @left.setter
    def left(self, value: 'IExpression'):
        self._left = value

    @property
    def right(self) -> 'IExpression':
        return self._right

    @right.setter
    def right(self, value: 'IExpression'):
        self._right = value

    def clone(self) -> 'AndExpression':
        return AndExpression(self.left.clone(), self.right.clone())

    def __str__(self):
        return f"[{self.left} && {self.right}]"


class OrExpression(BinaryExpression):
    def __init__(self, left: 'IExpression', right: 'IExpression'):
        self.left = left
        self.right = right

    @property
    def left(self) -> 'IExpression':
        return self._left

    @left.setter
    def left(self, value: 'IExpression'):
        self._left = value

    @property
    def right(self) -> 'IExpression':
        return self._right

    @right.setter
    def right(self, value: 'IExpression'):
        self._right = value

    def clone(self) -> 'OrExpression':
        return OrExpression(self.left.clone(), self.right.clone())

    def __str__(self):
        return f"[{self.left} || {self.right}]"
