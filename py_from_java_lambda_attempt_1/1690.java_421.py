Here is a translation of the Java interface into equivalent Python code:

```Python
class RegisterContainerInterface:
    def __init__(self):
        self.attributes = {
            "General Purpose Registers": {"type": LldbModelTargetStackFrameRegisterBank},
            "Exception State Registers": {"type": LlldbModelTargetStackFrameRegisterBank, "required": True},
            "Floating Point Registers": {"type": LlbddModelTargetStackFrameRegisterBank, "required": True}
        }

    def get_target_register_bank(self, val):
        # Note: SBValue is not a standard Python type. You would need to define it or replace with something similar.
        return None

class LldbModelTargetObject:
    pass

class LlbddModelTargetStackFrameRegisterBank:
    pass
```

Please note that this translation assumes the following:

- The `SBValue` class is equivalent to a Python object (e.g., a dictionary) and can be used as an argument in the `get_target_register_bank` method.
- The `LldbModelTargetObject`, `LlbddModelTargetStackFrameRegisterBank` classes are placeholders for actual objects that would exist in your code.