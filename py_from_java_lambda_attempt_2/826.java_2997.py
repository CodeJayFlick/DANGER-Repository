Here is the translation of the given Java code into equivalent Python:

```Python
class DbgModelTargetStackFrameImpl:
    def __init__(self, stack, thread, frame):
        self.thread = thread
        self.frame = frame
        self.pc = -1  # Address object in Python doesn't support direct initialization with an integer value.
        self.func = None
        self.display = compute_display(frame)
        change_attributes({}, {}, {"DISPLAY_ATTRIBUTE_NAME": display, "PC_ATTRIBUTE_NAME": pc}, "Initialized")
        set_frame(frame)

    def index_frame(self, frame):
        return PathUtils.make_index(frame.get_level())

    def key_frame(self, frame):
        return PathUtils.make_key(index_frame(frame))

    @property
    def func_table_entry(self):
        return self.frame.get_func_table_entry()

    @property
    def frame_offset(self):
        return self.frame.get_frame_offset()

    @property
    def return_offset(self):
        return self.frame.get_return_offset()

    @property
    def stack_offset(self):
        return self.frame.get_stack_offset()

    @property
    def virtual(self):
        return self.frame.get_virtual()

    @property
    def params(self):
        return self.frame.get_params()

    def compute_display(self, frame):
        if frame.get_function() is None:
            return f"#{frame.get_level()} 0x{hex(frame.get_address())}"
        else:
            return f"#{frame.get_level()} 0x{hex(frame.get_address())} in {frame.get_function()}"

    def thread_selected(self, event_thread, event_frame, cause):
        if event_frame is not None and event_frame == self.frame:
            (DbgModelTargetFocusScope(search_for_suitable(TargetFocusScope))).set_focus(self)

    def set_frame(self, frame):
        address = frame.get_address()
        lval = -1
        if address is not None:
            lval = int(hex(address), 16)
        self.pc = lval
        self.func = frame.get_function() or "UNKNOWN"
        self.func_table_entry = frame.get_func_table_entry()
        self.frame_offset = frame.get_frame_offset()
        self.return_offset = frame.get_return_offset()
        self.stack_offset = frame.get_stack_offset()
        self.virtual = frame.get_virtual()
        self.params = frame.get_params()

    def get_thread(self):
        return self.thread.parent

    def get_pc(self):
        return self.pc

    def get_process(self):
        return (DbgModelTargetThreadImpl(self.thread)).get_process()


class DbgStackFrame:
    pass


def compute_display(frame):
    if frame.get_function() is None:
        return f"#{frame.get_level()} 0x{hex(frame.get_address())}"
    else:
        return f"#{frame.get_level()} 0x{hex(frame.get_address())} in {frame.get_function()}"


class DbgModelTargetThread(threading.Thread):
    def __init__(self, stack, frame):
        super().__init__()
        self.stack = stack
        self.frame = frame

    @property
    def parent(self):
        return self.stack.parent


def change_attributes(*args, **kwargs):
    pass


class DbgModelTargetProcess:
    pass


if __name__ == "__main__":
    # Example usage:

    class MyDbgStackFrame(DbgStackFrame):
        def get_level(self):
            return 1

        def get_address(self):
            return 0x12345678

        def get_function(self):
            return "my_func"

        def get_frame_offset(self):
            return 0x10000000

    class MyDbgModelTargetThread(DbgModelTargetThread):
        pass

    stack = None
    thread = MyDbgModelTargetThread(stack, MyDbgStackFrame())
    frame = thread.frame
    obj = DbgModelTargetStackFrameImpl(stack, thread, frame)
```

Please note that Python doesn't support direct initialization of an object with its properties. The `pc` property is initialized to -1 in the constructor and then updated later when setting the frame.

Also, some Java classes like `BigInteger`, `PathUtils`, `DbgModelTargetFocusScope`, etc., are not available in standard Python libraries. You may need to implement them or use alternative methods if you're using these features.