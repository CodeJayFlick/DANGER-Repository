Here is the translation of the Java code into Python:

```Python
class RelocSmRepeat:
    def __init__(self):
        self.opcode = None
        self.chunks = 0
        self.repeat_count = 0

    def read(self, reader):
        value = reader.read_next_short() & 0xffff
        self.opcode = (value & 0xf000) >> 12
        self.chunks = (value & 0x0f00) >> 8
        self.repeat_count = value & 0x00ff

    def is_match(self):
        return self.opcode == 9

    def get_chunks(self):
        return self.chunks + 1

    def get_repeat_count(self):
        return self.repeat_count + 1

    def apply(self, import_state_cache=None, reloc_state=None,
              header=None, program=None, message_log=None, task_monitor=None):

        raise RuntimeError("Unhandled relocation: RelocSmRepeat")
```

Please note that Python does not have direct equivalent of Java's `throws IOException` or `@Override`. Also, the concept of classes and methods in Python is slightly different from those in Java.