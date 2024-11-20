Here is the translation of the Java code to Python:
```
class LldbProcessReplacedEvent:
    def __init__(self, info):
        super().__init__(info)

    def new_state(self) -> int:
        # NB: it's very tempting to relay the info we have, but
        #   doing so fouls up a lot of the tests because the stopped
        #   message arrives ahead of breakpointHit

        return None  # equivalent to Java's null return value
```
Note that I've removed the `StateType` import and replaced it with Python's built-in integer type (`int`). The `new_state()` method returns an integer, which is equivalent to Java's `null` return value.