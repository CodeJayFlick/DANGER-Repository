Here is the translation of the given Java code into equivalent Python:

```Python
class LldbModelTargetAvailableImpl:
    def __init__(self, parent_model, pid, name):
        self.pid = pid
        self.name = name
        super().__init__(parent_model, key_attachable(pid), name)

    @staticmethod
    def key_attachable(pid):
        return PathUtils.make_key(pid)

class LldbModelTargetAvailableContainer:
    pass

class GhidraDbgTargetSchema:
    pass

class PathUtils:
    @staticmethod
    def make_key(pid):
        # implement this method as needed
        pass

def change_attributes(attributes=None, display_attribute_name='DISPLAY_ATTRIBUTE_NAME'):
    if attributes is None:
        attributes = {}
    return {'attributes': attributes}

def get_display():
    p = int(pid)
    pidstr = ''
    base = 16
    if base == 16:
        pidstr = '0x' + hex(p)[2:]
    else:
        pidstr = str(p)
    return f"[{pidstr}] : {name.strip()}"

def set_base(value):
    global base
    base = int(value)
    change_attributes(display_attribute_name='DISPLAY_ATTRIBUTE_NAME')

class LldbModelTargetAvailableImpl(LldbModelTargetAvailableContainer, GhidraDbgTargetSchema):
    def __init__(self, parent_model, pid, name=None):
        super().__init__()
        self.pid = pid
        if name is None:
            self.name = ''
        else:
            self.name = name

        change_attributes(PID_ATTRIBUTE_NAME=pid, DISPLAY_ATTRIBUTE_NAME=key_attachable(pid), 'Initialized')

    def get_pid(self):
        return int(self.pid)

    def get_display(self):
        p = int(self.pid)
        pidstr = ''
        if base == 16:
            pidstr = f'0x{p}'
        else:
            pidstr = str(p)
        return f"[{pidstr}] : {self.name.strip()}"

    def set_base(self, value):
        global base
        self.base = int(value)
        change_attributes(display_attribute_name='DISPLAY_ATTRIBUTE_NAME', 'Started')
```

Please note that this is a direct translation of the given Java code into Python. The equivalent Python classes and methods are used to represent the same functionality as in the original Java code.