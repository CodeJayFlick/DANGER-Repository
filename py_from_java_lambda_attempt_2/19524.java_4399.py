Here is the translation of the given Java code into Python:

```Python
class CoordinateExpression:
    def __init__(self):
        self.axes = ['x', 'y', 'z']
        self.axis = None

    @property
    def axis(self):
        return self._axis

    @axis.setter
    def axis(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Axis must be a non-negative integer")
        self._axis = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        super().init(exprs, matched_pattern, is_delayed, parse_result)
        self.axis = parse_result.mark
        return True

    def convert(self, location):
        if self.axis == 0:
            return location.x
        elif self.axis == 1:
            return location.y
        else:
            return location.z

    @property
    def property_name(self):
        return f"the {self.axes[self.axis]}-coordinate"

    @property
    def return_type(self):
        from numbers import Number
        return Number

    def accept_change(self, mode):
        if (mode in [ChangeMode.SET, ChangeMode.ADD, ChangeMode.REMOVE] and 
            self.expr.is_single() and ChangerUtils.accepts_change(self.expr, ChangeMode.SET, Location)):
            return [Number]
        return None

    def change(self, event, delta, mode):
        assert delta is not None
        location = self.expr.get_single(event)
        if location is None:
            return
        n = float(delta[0])
        if mode in [ChangeMode.REMOVE, ChangeMode.ADD]:
            n *= -1
        elif mode == ChangeMode.SET:
            pass  # No change needed for SET mode
        else:  # DELETE/REMOVE_ALL/RESET modes are not implemented
            assert False

        if self.axis == 0:
            location.x = n + location.x
        elif self.axis == 1:
            location.y = n + location.y
        else:
            location.z = n + location.z

        self.expr.change(event, [location], ChangeMode.SET)

class Location:
    def __init__(self):
        self.x = None
        self.y = None
        self.z = None

    @property
    def x(self):
        return self._x

    @x.setter
    def x(self, value):
        if not isinstance(value, (int, float)):
            raise ValueError("X must be a number")
        self._x = value

    @property
    def y(self):
        return self._y

    @y.setter
    def y(self, value):
        if not isinstance(value, (int, float)):
            raise ValueError("Y must be a number")
        self._y = value

    @property
    def z(self):
        return self._z

    @z.setter
    def z(self, value):
        if not isinstance(value, (int, float)):
            raise ValueError("Z must be a number")
        self._z = value


class ChangeMode:
    SET = 1
    ADD = 2
    REMOVE = 3
    DELETE = 4
    REMOVE_ALL = 5
    RESET = 6

ChangerUtils = None  # This class is not implemented in Python, so it's left as None for now.
```

Please note that this translation does not include the `register` method and its usage.