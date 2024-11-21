Here is the translation of the given Java code into Python:

```Python
class VectorRotateXYZ:
    def __init__(self):
        self.axes = ['x', 'y', 'z']
        Skript.register_effect(self)

    @property
    def vectors(self):
        return None  # Replace with actual vector handling

    @vectors.setter
    def vectors(self, value):
        self._vectors = value

    @property
    def degree(self):
        return None  # Replace with actual number handling

    @degree.setter
    def degree(self, value):
        self._degree = value

    @property
    def axis(self):
        return None  # Replace with actual axis handling

    @axis.setter
    def axis(self, value):
        self._axis = value

    def init(self, expressions, matched_pattern, is_delayed, parse_result):
        if len(expressions) != 2:
            raise ValueError("Expected two expressions")
        self.vectors = expressions[0]
        self.degree = expressions[1]
        self.axis = parse_result.mark
        return True

    def execute(self, event):
        degree_value = self.degree.get(event)
        if degree_value is None:
            return
        for vector in self.vectors.get_array(event):
            if self.axis == 0:  # x-axis
                VectorMath.rotX(vector, degree_value.double())
            elif self.axis == 1:  # y-axis
                VectorMath.rotY(vector, degree_value.double())
            else:
                VectorMath.rotZ(vector, degree_value.double())

    def __str__(self):
        return f"rotate {self.vectors} around {self.axes[self.axis]}-axis by {self.degree}degrees"
```

Please note that this is a direct translation of the Java code into Python. You will need to replace `Vector`, `Number` and other types with their equivalent in your Python environment, as well as implement any necessary functionality for handling these types (e.g., vector math operations).