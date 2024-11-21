Here is the translation of the given Java code into Python:

```Python
class RepeatInstructionByteTracker:
    def __init__(self, repeat_pattern_limit: int, 
                 repeat_pattern_limit_ignored_region=None):
        self.repeat_pattern_limit = repeat_pattern_limit
        self.repeat_pattern_limit_ignored_region = repeat_pattern_limit_ignored_region

    def reset(self) -> None:
        self.repeat_pattern_cnt = 0

    def exceeds_repeat_byte_pattern(self, inst: dict) -> bool:
        if not self.repeat_pattern_limit > 0:
            return False
        
        if self.repeat_pattern_limit_ignored_region and \
           self.repeat_pattern_limit_ignored_region.contains(inst['address']):
            self.reset()
            return False
        
        repeated_byte = inst.get('repeated_byte')
        
        if repeated_byte is None:
            self.reset()
        elif repeated_byte == self.repeat_byte_value:
            self.repeat_pattern_cnt += 1
            if self.repeat_pattern_cnt > self.repeat_pattern_limit:
                self.reset()
                return True
        else:
            self.repeat_byte_value = repeated_byte
            self.repeat_pattern_cnt = 1
        
        return False

    def set_repeat_pattern_limit(self, max_instructions: int) -> None:
        self.repeat_pattern_limit = max_instructions

    def set_repeat_pattern_limit_ignored_region(self, region):
        self.repeat_pattern_limit_ignored_region = region


# Example usage
tracker = RepeatInstructionByteTracker(5)
print(tracker.exceeds_repeat_byte_pattern({'address': 0x10000000, 'repeated_byte': b'\x01'}))  # False
print(tracker.exceeds_repeat_byte_pattern({'address': 0x10000002, 'repeated_byte': b'\x01'}))  # True

tracker.set_repeat_pattern_limit(10)
print(tracker.exceeds_repeat_byte_pattern({'address': 0x10000003, 'repeated_byte': b'\x01'}))  # False
```

Note that the `PseudoInstruction` class is not present in Python. In this translation, I replaced it with a dictionary (`inst`) which contains an `'address'` key and a `'repeated_byte'` key.