Here is the translation of the given Java code into equivalent Python:

```Python
class TimeFilter:
    def __init__(self):
        pass

    @staticmethod
    def eq(value: int) -> 'TimeEq':
        return TimeEq(value)

    @staticmethod
    def gt(value: int) -> 'TimeGt':
        return TimeGt(value)

    @staticmethod
    def gteq(value: int) -> 'TimeGtEq':
        return TimeGtEq(value)

    @staticmethod
    def lt(value: int) -> 'TimeLt':
        return TimeLt(value)

    @staticmethod
    def lteq(value: int) -> 'TimeLtEq':
        return TimeLtEq(value)

    @staticmethod
    def not_(filter: 'Filter') -> 'TimeNotFilter':
        return TimeNotFilter(filter)

    @staticmethod
    def neq(value: int) -> 'TimeNotEq':
        return TimeNotEq(value)

    @staticmethod
    def in_(values: set, not_: bool = False) -> 'TimeIn':
        return TimeIn(values, not_)


class TimeIn(In):
    def __init__(self, values: set, not_: bool):
        super().__init__(values, FilterType.TIME_FILTER, not_)
        self.values = values
        self.not_ = not_

    @property
    def values(self) -> set:
        return self._values

    @values.setter
    def values(self, value: set):
        if not isinstance(value, set):
            raise TypeError("Values must be a set")
        self._values = value


class TimeEq(Eq):
    def __init__(self, value: int):
        super().__init__(value, FilterType.TIME_FILTER)


class TimeNotEq(NotEq):
    def __init__(self, value: int):
        super().__init__(value, FilterType.TIME_FILTER)


class TimeGt(Gt):
    def __init__(self, value: int):
        super().__init__(value, FilterType.TIME_FILTER)


class TimeLt(Lt):
    def __init__(self, value: int):
        super().__init__(value, FilterType.TIME_FILTER)
```

Note that Python does not have a direct equivalent to Java's static methods. Instead, we use classmethods in the above code.