Here is the translation of the given Java code into equivalent Python:

```Python
import concurrent.futures as futures
from collections import deque

class TestTargetInterpreter:
    def __init__(self, parent):
        self.parent = parent
        self.queue_execute = deque()
        self.queue_capture = deque()

    class ExecuteCall(futures.Future):
        def __init__(self, cmd):
            super().__init__()
            self.cmd = cmd

    def execute(self, cmd):
        with futures.Lock():
            f = TestTargetInterpreter.ExecuteCall(cmd)
            self.queue_execute.appendleft(f)
            return f

    def execute_capture(self, cmd):
        with futures.Lock():
            f = TestTargetInterpreter.ExecuteCall(cmd)
            self.queue_capture.appendleft(f)
            return f

    def set_display(self, display):
        # implement changeAttributes method
        pass

    def set_prompt(self, prompt):
        # implement changeAttributes method
        pass

    def output(self, channel, line):
        print(line)

    def clear_calls(self):
        with futures.Lock():
            self.queue_execute.clear()
            self.queue_capture.clear()

    def poll_execute(self):
        with futures.Lock():
            return self.queue_execute.pop() if self.queue_execute else None

    def poll_capture(self):
        with futures.Lock():
            return self.queue_capture.pop() if self.queue_capture else None
```

Please note that this is a direct translation of the given Java code into equivalent Python. The actual implementation might vary based on your specific requirements and constraints in Python.