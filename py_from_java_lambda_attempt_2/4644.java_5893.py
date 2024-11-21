Here is the translation of the Java code to Python:

```Python
class StateMachine:
    def __init__(self):
        self.address = 0
        self.file = 1
        self.line = 1
        self.column = 0
        self.is_statement = False
        self.is_basic_block = False
        self.is_end_sequence = False

    def reset(self, default_is_statement=True):
        self.address = 0
        self.file = 1
        self.line = 1
        self.column = 0
        self.is_statement = default_is_statement
        self.is_basic_block = False
        self.is_end_sequence = False

    def print(self):
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"ADDR={self.address:x}")
        logger.info(" ")
        logger.info(f"FILE={self.file}")
        logger.info(" ")
        logger.info(f"LINE={self.line}")
        logger.info(" ")
        logger.info(f"COL={self.column}")

# Example usage:
if __name__ == "__main__":
    state_machine = StateMachine()
    state_machine.reset(default_is_statement=True)
    state_machine.print()
```

Please note that Python does not have a direct equivalent to Java's `Msg` class. I used the built-in logging module for printing messages in this translation.