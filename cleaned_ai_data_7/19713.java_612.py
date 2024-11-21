class VectorBetweenLocations:
    def __init__(self):
        self.from = None
        self.to = None

    @staticmethod
    def register_expression():
        pass  # This part doesn't have an exact equivalent in Python, as it's related to registering a function with Skript. It can be removed or replaced.

    def init(self, exprs: list):
        if len(exprs) != 2:
            return False

        self.from = LocationExpression(exprs[0])
        self.to = LocationExpression(exprs[1])

        return True

    def get(self, event=None):
        l1 = self.from.get(event)
        l2 = self.to.get(event)

        if not (l1 and l2):
            return None

        vector = Vector(l2.x - l1.x, l2.y - l1.y, l2.z - l1.z)
        return [vector]

    def is_single(self) -> bool:
        return True

class LocationExpression:
    def __init__(self, expr: object):
        self.expr = expr

    def get(self, event=None):
        if not hasattr(self.expr, 'get'):
            raise Exception('Invalid expression')

        try:
            value = self.expr.get(event)
            return value
        except Exception as e:
            print(f"Error in {self.expr}: {e}")
            return None


class Vector(tuple):
    def __new__(cls, x: float, y: float, z: float):
        return super().__new__((x, y, z))

    @property
    def x(self) -> float:
        return self[0]

    @property
    def y(self) -> float:
        return self[1]

    @property
    def z(self) -> float:
        return self[2]
