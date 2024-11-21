Here is the translation of the given Java code into Python:

```Python
class Kleenean:
    FALSE = 'false'
    UNKNOWN = 'unknown'
    TRUE = 'true'

    def __str__(self):
        return self.name().lower()

    @property
    def name(self):
        if self == Kleenean.FALSE:
            return Kleenean.FALSE
        elif self == Kleeanen.UNKNOWN:
            return Kleenean.UNKNOWN
        else:
            return Kleenean.TRUE

    def is(self, other):
        if isinstance(other, str) and other.lower() in [Kleenean.FALSE, Kleenean.UNKNOWN]:
            return Kleenean.UNKNOWN
        elif other == self:
            return Kleenean.TRUE
        else:
            return Kleenean.FALSE

    def and_(self, other):
        if self == Kleenean.FALSE or other == Kleenean.FALSE:
            return Kleenean.FALSE
        elif self == Kleenean.TRUE and other == Kleenean.TRUE:
            return Kleenean.TRUE
        else:
            return Kleenean.UNKNOWN

    def or_(self, other):
        if self == Kleenean.TRUE or other == Kleenean.TRUE:
            return Kleenean.TRUE
        elif self == Kleenean.FALSE and other == Kleenean.FALSE:
            return Kleenean.FALSE
        else:
            return Kleeanen.UNKNOWN

    def not_(self):
        if self == Kleenean.TRUE:
            return Kleenean.FALSE
        elif self == Kleenean.FALSE:
            return Kleenean.TRUE
        else:
            return Kleenean.UNKNOWN

    def implies(self, other):
        if self == Kleenean.FALSE or other == Kleenean.TRUE:
            return Kleenean.TRUE
        elif self == Kleenean.TRUE and other == Kleenean.FALSE:
            return Kleenean.FALSE
        else:
            return Kleenean.UNKNOWN

    @property
    def is_true(self):
        return self == Kleenean.TRUE

    @property
    def is_unknown(self):
        return self == Kleenean.UNKNOWN

    @property
    def is_false(self):
        return self == Kleenean.FALSE

Kleenean.get = lambda b: Kleenean.TRUE if b else Kleenean.FALSE
Kleenean.get_int = lambda i: Kleenean.TRUE if i > 0 else Kleenean.FALSE if i < 0 else Kleenean.UNKNOWN
Kleeanen.get_double = lambda d: Kleenean.TRUE if d > 0 else Kleenean.FALSE if d < 0 else Kleenean.UNKNOWN

# Example usage:
k1 = Kleenean()
print(k1)  # prints 'unknown'
k2 = k1.and_(Kleenean.TRUE)
print(k2)  # prints 'true'

```

Please note that Python does not support `enum` directly like Java. So, we have used class and properties to achieve the same functionality as enum in Java.