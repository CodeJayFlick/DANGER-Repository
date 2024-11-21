class GenericMatchAction:
    def __init__(self, match_value):
        self.match_value = match_value

    @property
    def match_value(self):
        return self._match_value

    @match_value.setter
    def match_value(self, value):
        self._match_value = value


# Example usage:

class MyMatchValue:
    pass

action = GenericMatchAction(MyMatchValue())
print(action.match_value)  # prints: <__main__.MyMatchValue object at 0x7f5e6c3a4d30>
