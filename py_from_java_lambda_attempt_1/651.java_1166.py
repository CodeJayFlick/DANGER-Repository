Here is a translation of the Java code into equivalent Python:

```Python
class DbgStackListFramesCommand:
    def __init__(self, manager, thread):
        self.manager = manager
        self.thread = thread
        self.result = []

    def complete(self, pending):
        return self.result

    def invoke(self):
        result = []
        so = self.manager.get_system_objects()
        previous_thread_id = so.current_thread_id
        so.set_current_thread_id(self.thread.id)
        stack_trace = self.manager.control.get_stack_trace(0L, 0L, 0L)
        for i in range(stack_trace.number_of_frames):
            tf = stack_trace.frame(i)
            frame = DbgStackFrameImpl(
                self.thread,
                tf.frame_number,
                BigInteger(long_to_hex(tf.instruction_offset)),
                tf.func_table_entry,
                tf.frame_offset,
                tf.return_offset,
                tf.stack_offset,
                tf.virtual,
                *tf.params
            )
            result.append(frame)
        so.set_current_thread_id(previous_thread_id)

class DbgStackFrameImpl:
    def __init__(self, thread, frame_number, instruction_offset, func_table_entry, frame_offset, return_offset, stack_offset, virtual, params):
        self.thread = thread
        self.frame_number = frame_number
        self.instruction_offset = instruction_offset
        self.func_table_entry = func_table_entry
        self.frame_offset = frame_offset
        self.return_offset = return_offset
        self.stack_offset = stack_offset
        self.virtual = virtual
        self.params = params

def long_to_hex(long_value):
    return hex(int(str(long_value)))[2:]
```

Note that this translation is not a direct equivalent of the Java code, but rather an attempt to capture its essence in Python.