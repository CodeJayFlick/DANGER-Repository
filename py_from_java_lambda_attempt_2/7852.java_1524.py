Here's your Java code translated into Python:

```Python
class MDManagedProperties:
    def __init__(self, dmang, is_pointer=False, is_reference=False):
        self.is_pointer = is_pointer
        self.is_reference = is_reference
        super().__init__(dmang)

    @property
    def is_gc(self):
        return self._is_gc

    @property
    def is_pin(self):
        return self._is_pin

    @property
    def is_c(self):
        return self._is_c

    # @property
    # def is_f(self):
    #     return self._is_f

    # @property
    # def is_h(self):
    #     return self._is_h

    # @property
    # def is_q(self):
    #     return self._is_q

    @property
    def special(self):
        return self._special

    def parse_internal(self, dmang):
        ch = dmang.peek()
        if ch == '$':
            dmang.increment()
            ch = dmang.get_and_increment()
            match ch:
                case 'A':
                    self._is_gc = True
                    self._is_pin = False
                    self.special = '^'
                    break
                case 'B':
                    self._is_pin = True
                    self.special = '*'
                    break
                case 'C':
                    self._is_c = True
                    self.special = '%'
                    break
                # case 'F':  # Not implemented yet
                #     pass
                # case 'H':  # Not implemented yet
                #     pass
                # case 'Q':  # Not implemented yet
                #     pass

        elif ch >= '0' and ch <= '9':
            self._array_rank = int(ch)
        else:
            raise MDException("Invalid CLI: array rank")

    def emit(self, type_name):
        if '*' == type_name:
            if self.is_gc:
                return '^'
            elif self.is_c:
                return '%'

        # No change for is_pin
        return type_name

class MDParsableItem:
    pass

class MDException(Exception):
    pass
```

Please note that Python does not support direct translation of Java code. The above Python code has been written manually, taking into account the functionality and logic present in your original Java code.