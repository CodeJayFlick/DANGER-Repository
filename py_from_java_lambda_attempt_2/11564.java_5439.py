Here's your Java code translated into Python:

```Python
class BreakTable:
    def __init__(self):
        pass

    # Associate a particular emulator with breakpoints in this table
    def set_emulate(self, emu):
        pass  # This method is abstract and doesn't do anything. In Python, you would typically raise an exception if someone tries to call it.

    # Invoke any breakpoints associated with this particular pcodeop
    def do_pcode_op_break(self, curop):
        return False  # If there was a breakpoint and it replaced the action of the pcode op, then True is returned. In Python, we'll just always return False for now.

    # Invoke any breakpoints associated with this machine address
    def do_address_break(self, addr):
        return False  # If there was a breakpoint that replaced the action of the machine instruction, then True is returned. In Python, we'll just always return False for now.
```

Note: The `setEmulate` method in Java doesn't actually set anything and returns nothing (`void`). Similarly, this Python class does not do any actual work when you call these methods.