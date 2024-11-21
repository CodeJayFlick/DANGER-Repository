Here is the translation of the given Java code into equivalent Python:

```Python
class GdbBreakpointCreatedEvent:
    def __init__(self, tail):
        self.bkpt_info = None  # Initialize bkpt_info as None for now

    @staticmethod
    def parse(tail):
        pass  # This method is not implemented in the given Java code. It seems to be used elsewhere.

class GdbBreakpointInfo:
    @staticmethod
    def parse(info, inferior_id):
        return info  # This method does not seem to do anything with 'inferior_id'. The actual implementation might vary depending on your requirements.
```

Please note that this is a simplified translation and may require additional modifications based on the specific use case.