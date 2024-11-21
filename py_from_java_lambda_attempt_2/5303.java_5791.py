Here is the translation of the given Java code into Python:

```Python
class AbstractLineDispenser:
    def __init__(self):
        self.is_html = False
        self.width = 0
        self.fill_amount = 0
        self.prefix = ""
        self.index = 0

    @abstractmethod
    def has_more_lines(self):
        pass

    @abstractmethod
    def get_next_line(self):
        pass

    @abstractmethod
    def dispose(self):
        pass

def unique_address_string(addr):
    return str(addr)

# This function is not used in the given code, so I'm commenting it out.
# def address_space_get_space_id_overlay_id_offset(addr):
#     return f"{addr.get_address_space().get_space_id()}_{addr.get_overlay_id()}_{addr.get_offset()}_"

def get_fill(amt):
    fill = ""
    for i in range(0, amt):
        fill += "  "
    return fill

def this_get_fill(self):
    amt = self.fill_amount + (self.has_more_lines() if hasattr(self, 'has_more_lines') else self.width)
    return get_fill(amt)

def clip(s, width):
    return clip(s, width, True, True)

def clip(s, width, pad_if_shorter, left_justify):
    if width < 0:
        return ""

    # If length of s is less than len,
    # then we need to pad it...
    if len(s) <= width:
        if left_justify:
            return s + (get_fill(width - len(s)) if pad_if_shorter else "")
        return get_fill(width - len(s)) if pad_if_shorter else "" + s

    match width:
        case 0: return ""
        case 1: return "."
        case 2: return ".."
        case 3: return "..."
        case _: return s[:width-3] + "..."

# This function is not used in the given code, so I'm commenting it out.
# def get_unique_address_string(addr):
#     #return addr.get_address_space().get_space_id() + "_" + addr.get_overlay_id() + "_" + str(addr.get_offset())
#     return unique_address_string(addr)
```

Please note that Python does not support static methods like Java. Also, the `@abstractmethod` decorator is used to mark abstract methods in Python, but it's not strictly necessary as you can still use the same method name and parameters for any subclass implementation.