Here is the translation of the Java code into Python:

```Python
class DbgBreakpointInfo:
    def __init__(self, old_info=None, enabled=False):
        self.bpt = None
        self.proc = None
        self.event_thread = None
        self.number = 0
        self.enabled = enabled

        if old_info is not None:
            self.set_breakpoint(old_info.get_debug_breakpoint())
            self.proc = old_info.get_proc()
            self.event_thread = old_info.get_event_thread()

    def set_breakpoint(self, bpt):
        self.bpt = bpt
        self.number = bpt.id
        self.bpt_type = bpt.type
        self.flags = bpt.flags

        if isinstance(bpt.type.break_type, BreakType) and bpt.type.break_type == BreakType.DATA:
            self.parameters = bpt.data_parameters
            self.access = self.parameters.access
            self.size = self.parameters.size
        else:
            self.offset = bpt.offset
            self.expression = bpt.get_offset_expression()

    def __hash__(self):
        return hash((self.number, self.bpt_type, tuple(self.flags), self.enabled, tuple(self.access), self.size, self.offset, self.expression))

    @property
    def id(self):
        return self.bpt.id

    def __str__(self):
        return f"<DbgBreakpointInfo number={self.number}, type={self.get_type()}, flags={self.flags}, addr={self.offset}, times=0, size={self.size}>"

    def get_number(self):
        return self.number

    @property
    def enabled(self):
        if isinstance(self.bpt.type.break_type, BreakType) and self.bpt.type.break_type == BreakType.DATA:
            return any(flag in [BreakFlags.ENABLED] for flag in self.flags)
        else:
            return True  # assume enabled by default

    @enabled.setter
    def enabled(self, value):
        if isinstance(self.bpt.type.break_type, BreakType) and self.bpt.type.break_type == BreakType.DATA:
            self.flags = [flag for flag in self.flags if flag not in [BreakFlags.ENABLED]] + ([BreakFlags.ENABLED] if value else [])
        else:
            pass  # assume enabled by default

    def get_type(self):
        if isinstance(self.bpt.type.break_type, BreakType) and self.bpt.type.break_type == BreakType.CODE:
            return "BREAKPOINT"
        elif self.parameters is not None and any(access in [BreakAccess.READ, BreakAccess.WRITE] for access in self.access):
            return "ACCESS_WATCHPOINT" if all(access in [BreakAccess.READ] for access in self.access) else ("READ_WRITE_WATCHPOINT" if len(set(self.access)) == 2 else "HW_WATCHPOINT")
        elif self.parameters is not None and any(access in [BreakAccess.EXECUTE] for access in self.access):
            return "HW_BREAKPOINT"
        else:
            return "OTHER"

    def get_expression(self):
        return self.expression

    @property
    def size(self):
        if isinstance(self.bpt.type.break_type, BreakType) and self.bpt.type.break_type == BreakType.DATA:
            return self.parameters.size
        else:
            return 1

    @size.setter
    from functools import partial
    get_size = partial(setattr, None, 'size')

    def get_access(self):
        if isinstance(self.bpt.type.break_type, BreakType) and self.bpt.type.break_type == BreakType.DATA:
            return self.access
        else:
            return [BreakAccess.EXECUTE]

    @property
    from functools import partial
    get_offset = partial(setattr, None, 'offset')

    def with_enabled(self, enabled):
        if self.enabled == enabled:
            return self
        else:
            return DbgBreakpointInfo(old_info=self, enabled=enabled)

    def get_debug_breakpoint(self):
        return self.bpt

    @property
    from functools import partial
    get_flags = partial(setattr, None, 'flags')

    def get_proc(self):
        return self.proc

    @property
    from functools import partial
    get_event_thread = partial(setattr, None, 'event_thread')
```

Note that I have made some assumptions about the Python code. For example, in Java you can use `@Override` to indicate that a method is overriding one from its superclass. In Python, this isn't necessary because it's not possible for two methods with different names and signatures to be overridden by accident.

Also note that there are several places where I have simply copied the original code without translating it into Python. For example, in Java you can use `Objects.equals` to compare objects for equality. In Python, this isn't necessary because all objects are equal if they have the same hash value and identity.