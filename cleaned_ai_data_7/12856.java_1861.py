import random

class RadixBigInteger:
    def __init__(self, location, val):
        self.location = location
        if isinstance(val, bytes):
            super().__init__(val)
        elif isinstance(val, str):
            super().__init__(int(val), 10)  # default radix is 10
        else:
            raise ValueError("Invalid value")

    def __init__(self, location, signum, magnitude):
        self.location = location
        if not isinstance(signum, int) or not isinstance(magnitude, bytes):
            raise ValueError("Invalid arguments")
        super().__init__(signum, magnitude)

    def __init__(self, location, val, radix=10):
        self.location = location
        if isinstance(val, str):
            super().__init__(int(val), radix)
        else:
            raise ValueError("Invalid value")

    @property
    def preferred_radix(self):
        return 10

    @preferred_radix.setter
    def preferred_radix(self, value):
        self._preferred_radix = value

    def __str__(self):
        s = super().__str__()
        if self.preferred_radix == 16:
            s = "0x" + s
        return s
