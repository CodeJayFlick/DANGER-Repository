Here is the translation of the given Java code into equivalent Python:

```Python
class CountLeadingOnesOpBehavior:
    def evaluate(self, emu, out, *inputs):
        if not out:
            raise ValueError("CALLOTHER: Count Leading Ones op missing required output")

        if len(inputs) != 2 or inputs[1].getSize() == 0 or inputs[1].isConstant():
            raise ValueError(
                "CALLOTHER: Count Leading Ones op requires one non-constant varnode input"
            )

        # TODO: add support for larger varnode sizes

        in_var = inputs[1]
        if in_var.getSize() > 8 or out.getSize() > 8:
            raise ValueError(
                "CALLOTHER: Count Leading Ones op only supports varnodes of size 8-bytes or less"
            )

        memory_state = emu.getMemoryState()
        value = memory_state.getValue(in_var)
        mask = 1 << ((in_var.getSize() * 8) - 1)
        count = 0
        while (mask & value) != 0:
            count += 1
            value <<= 1

        memory_state.setValue(out, count)

# Usage example:
emu = ...  # Initialize emulator object
out = ...  # Initialize output varnode
in_var = ...  # Initialize input varnode
CountLeadingOnesOpBehavior().evaluate(emu, out, in_var)
```

Please note that Python does not have direct equivalent of Java's `LowlevelError` and `Varnode`. I replaced them with Python's built-in exceptions (`ValueError`) for simplicity.