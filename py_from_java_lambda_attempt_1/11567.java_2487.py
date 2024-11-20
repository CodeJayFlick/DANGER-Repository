Here is the translation of the given Java code into Python:

```Python
class CountLeadingZerosOpBehavior:
    def evaluate(self, emu, out, *inputs):
        if out is None:
            raise ValueError("CALLOTHER: Count Leading Zeros op missing required output")

        if len(inputs) != 2 or inputs[1].getSize() == 0 or inputs[1].isConstant():
            raise ValueError(
                "CALLOTHER: Count Leading Zeros op requires one non-constant varnode input"
            )

        # TODO: add support for larger varnode sizes

        in_var = inputs[1]
        if in_var.getSize() > 8 or out.getSize() > 8:
            raise ValueError(
                "CALLOTHER: Count Leading Zeros op only supports varnodes of size 8-bytes or less"
            )

        memory_state = emu.get_memory_state()
        value = memory_state.get_value(in_var)
        mask = 1 << ((in_var.getSize() * 8) - 1)
        count = 0
        while mask != 0:
            if (mask & value) != 0:
                break
            count += 1
            mask >>= 1

        memory_state.set_value(out, count)

# Example usage:
emu = ...  # Initialize emulator object
out_var = ...  # Initialize output varnode
in_var = ...  # Initialize input varnode
CountLeadingZerosOpBehavior().evaluate(emu, out_var, in_var)
```

Please note that this translation is not perfect and some parts of the code might need adjustments according to your specific Python environment.