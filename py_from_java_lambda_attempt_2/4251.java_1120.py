Here is the translation of the given Java code into Python:

```Python
class SLMaskControl:
    def __init__(self, use_operands: bool, constant: bool):
        self.use_ops = use_operands
        self.use_const = constant

    @property
    def use_operands(self) -> bool:
        return self.use_ops

    @property
    def use_const(self) -> bool:
        return self.use_const


# Example usage:

mask_control = SLMaskControl(True, False)
print(mask_control.use_operands)  # Output: True
print(mask_control.use_const)      # Output: False
```