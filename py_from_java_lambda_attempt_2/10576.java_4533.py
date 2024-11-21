Here is the translation of the given Java code into Python:

```Python
class GTimerMonitor:
    DUMMY = type('DUMMY', (), {
        'was_cancelled': lambda self: False,
        'did_run': lambda self: False,
        'cancel': lambda self: False
    })

    def __init__(self):
        pass

    def cancel(self) -> bool:
        # TO DO: implement the actual cancellation logic here
        return False

    def did_run(self) -> bool:
        # TO DO: implement the actual check for whether the timer has run or not here
        return False

    def was_cancelled(self) -> bool:
        # TO DO: implement the actual check for whether the timer was cancelled or not here
        return False


# Example usage:

monitor = GTimerMonitor()
print(monitor.cancel())  # prints: False (assuming no cancellation logic implemented)
print(monitor.did_run())  # prints: False (assuming no run detection logic implemented)
print(monitor.was_cancelled())  # prints: False (assuming no cancellation check logic implemented)

```

Please note that the actual implementation of `cancel`, `did_run` and `was_cancelled` methods depends on your specific use case. The above Python code is just a translation of the given Java interface into equivalent Python syntax, without any actual functionality.