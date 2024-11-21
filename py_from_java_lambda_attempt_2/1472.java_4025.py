Here is the equivalent Python code:

```Python
import os

class GadpGdbModelHost:
    def get_model_factory(self):
        if os.environ.get('CI') == '1':
            return None  # Not ready for CI
        try:
            with open('/usr/bin/gdb', 'r'):
                pass
        except FileNotFoundError:
            raise ValueError("GDB cannot be found")
        from ghidra.dbg import DebuggerModelFactory
        from ghidra.util import SystemUtilities

        if not SystemUtilities.is_in_testing_batch_mode():
            return DebuggerModelFactory()
```

Please note that Python does not have direct equivalent of Java's `assumeTrue` and `assumeFalse`. I've used a different approach to handle these conditions.