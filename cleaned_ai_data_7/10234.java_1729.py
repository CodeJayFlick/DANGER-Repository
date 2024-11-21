class Pair:
    def __init__(self, key=None, value=None):
        self.first = key
        self.second = value

    @staticmethod
    def empty_pair():
        return Pair(None, None)

    def __str__(self):
        return f"<{self.first},{self.second}>"

    def __hash__(self):
        prime = 31
        result = 1
        if self.first is not None:
            result *= prime + hash(self.first)
        else:
            result += 0

        if self.second is not None:
            result *= prime + hash(self.second)
        else:
            result += 0

        return result

    def __eq__(self, other):
        if self == other: 
            return True
        elif other is None: 
            return False
        elif type(self) != type(other): 
            return False
        
        other = other.__dict__
        
        if not (isinstance(self.first, type(other['first'])) and isinstance(self.second, type(other['second']))):
            return False

        return self.first == other['first'] and self.second == other['second']
