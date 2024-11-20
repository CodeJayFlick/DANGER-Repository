Here is the translation of the given Java code into Python:

```Python
class BasicBlockCounterFunctionAlgorithm:
    def __init__(self):
        pass

    def get_name(self):
        return "Basic Block Count"

    def score(self, function, monitor=None):
        program = function.get_program()
        block_model = BasicBlockModel(program)

        body = function.get_body()
        max_iterations = len(body)
        if monitor:
            monitor.initialize(max_iterations)

        iterator = block_model.get_code_blocks_containing(body, monitor)

        block_count = 0
        while iterator.has_next():
            if monitor and monitor.is_cancelled():
                break
            iterator.next()
            block_count += 1
            if monitor:
                monitor.increment_progress(1)
            # artificial sleep for demo purposes
            time.sleep(0.05)

        return block_count

    def artificial_sleep_for_demo_purposes(self):
        try:
            time.sleep(0.05)
        except Exception as e:
            pass


class BasicBlockModel:
    def __init__(self, program):
        self.program = program

    def get_code_blocks_containing(self, body, monitor=None):
        # implement this method
        pass


from ghidra import Program, CodeBlockIterator, AddressSetView, Function, TaskMonitor
import time
```

Please note that the `BasicBlockModel` class is not fully implemented in Python as it was a part of Java's Ghidra API. You would need to implement this method according to your specific requirements.

Also, I used `time.sleep(0.05)` instead of `Thread.sleep(50)` because sleep time should be less than 1 second for most operating systems and you can adjust the value as per your requirement.