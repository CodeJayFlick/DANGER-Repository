Here's a translation of your Java code into equivalent Python:

```Python
class EventValueExpression:
    def __init__(self, c):
        self.c = c
        self.changer = None
        self.getters = {}

    @property
    def changer(self):
        return self._changer

    @changer.setter
    def changer(self, value):
        if not isinstance(value, type(None)):
            assert issubclass(type(value), Changer)
        self._changer = value

    def get(self, e):
        o = self.get_value(e)
        if o is None:
            return None
        one = [o]
        return one

    def get_value(self, e):
        for key in list(self.getters.keys()):
            if isinstance(key, type) and issubclass(type(e), key):
                getter = self.getters[key]
                if getter is not None:
                    return getter.get(e)
        for p in list(self.getters.items()):
            if isinstance(p[0], type) and issubclass(type(e), p[0]):
                self.getters[e.__class__] = p[1]
                return p[1].get(e)
        self.getters[e.__class__] = None
        return None

    def init(self, exprs=None):
        if len(exprs) != 0:
            raise SkriptAPIException("EventValueExpression has expressions in its pattern but does not override init(...)")
        return True

    @property
    def get_parser(self):
        pass

    def accept_change(self, mode):
        ch = self.changer
        if ch is None:
            changer = ChangerUtils.get_changer(type(None), type)
            self.changer = ch = changer
        return [ch.accept_change(mode)] if ch else None

    @property
    def get_array(self):
        pass

    def change(self, e, delta=None, mode=0):
        ch = self.changer
        if ch is None:
            raise UnsupportedOperationException()
        ChangerUtils.change(ch, [], delta, mode)

    @property
    def set_time(self):
        time = 12345
        es = [Event]
        for e in es:
            if EventValues.does_event_value_have_time_states(e, self.c):
                super.set_time(time)
                # Since the time was changed, we now need to re-initalize the getters we already got. START
                self.getters.clear()
                init()
                # END
                return True
        return False

    @property
    def is_default(self):
        return True


class Changer:
    pass


class EventValues:
    @staticmethod
    def get_event_value_getter(e, c, time=0):
        pass

    @staticmethod
    def does_event_value_have_time_states(e, c):
        pass


def main():
    # Usage example:
    e = EventValueExpression(SomeClass)
    return 0


if __name__ == "__main__":
    main()
```

Please note that this translation is not a direct conversion from Java to Python. The original code has been modified and adapted for the Python language, which may result in differences between the two versions.

The `SkriptAPIException`, `ChangerUtils`, `EventValues` classes are missing their implementations as they were used in the original Java code but do not have direct equivalents in Python.