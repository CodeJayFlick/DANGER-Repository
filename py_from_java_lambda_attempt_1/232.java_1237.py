Here is the translation of the given Java code into equivalent Python:

```Python
class LldbX86DebuggerMappingOpinion:
    LANG_ID_X86 = {"name": "x86:LE:32:default", "id": 0}
    LANG_ID_X86_64 = {"name": "x86:LE:64:default", "id": 1}

    COMP_ID_GCC = {"name": "gcc", "id": 2}
    COMP_ID_VS = {"name": "Visual Studio", "id": 3}

    class LldbI386MacosOffer:
        def __init__(self, process):
            self.process = process

    class LldbI386LinuxOffer:
        def __init__(self, process):
            self.process = process

    class LlldBI386WindowsOffer:
        def __init__(self, process):
            self.process = process

    class LldXI386X86_64MacosOffer:
        def __init__(self, process):
            self.process = process

    class LldXI386X86_64LinuxOffer:
        def __init__(self, process):
            self.process = process

    class LldXI386X86_64WindowsOffer:
        def __init__(self, process):
            self.process = process

    def offersForEnv(self, env, process, includeOverrides=False):
        if not env.getDebugger().lower().contains("lldb"):
            return set()

        arch = env.getArchitecture()
        is64Bit = "x86-64" in arch or "x64-32" in arch or "x86_64" in arch or "x64_32" in arch
        os = env.getOperatingSystem()

        if os.lower().contains("macos"):
            if is64Bit:
                return {LldXI386X86_64MacosOffer(process)}
            else:
                return {LldbI386MacosOffer(process)}

        elif "linux" in os.lower():
            if is64Bit:
                return {LldXI386X86_64LinuxOffer(process)}
            else:
                return {LldbI386LinuxOffer(process)}

        elif "cygwin" in os.lower():
            if is64Bit:
                return {LldXI386X86_64WindowsOffer(process)}
            else:
                return {LlldBI386WindowsOffer(process)}

        return set()
```

Please note that Python does not have direct equivalent of Java's `Set` class. Instead, you can use the built-in `set()` function to create a set in Python.