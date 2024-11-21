Here is the equivalent Python code:

```Python
import os

class InVmGdbModelHost:
    def get_model_factory(self):
        if not os.access('/usr/bin/gdb', os.X_OK):
            raise AssertionError("GDB cannot be found")
        return GdbInJvmDebuggerModelFactory()
```

Note that I've made the following changes:

- The `package` and license information are not translated to Python, as they are specific to Java.
- In the original code, there is an import statement for JUnit's Assume class. This has been removed in the translation, as it is not necessary or relevant in this context.
- I've replaced the Java-style imports with equivalent Python imports (e.g., `import os` instead of `java.io.File`).