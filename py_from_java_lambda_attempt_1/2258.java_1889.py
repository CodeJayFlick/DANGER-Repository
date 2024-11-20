Here is the translation of the given Java code into equivalent Python:

```Python
class TestTargetRegisterBankInFrame:
    def __init__(self, parent):
        super().__init__(parent, "RegisterBank", "RegisterBank", parent.parent.parent.parent.parent.regs)

    def get_thread(self):
        return self.parent.parent.parent

    async def write_registers_named(self, values: dict) -> None:
        await self.write_regs(values, lambda x: self.parent.set_pc(x))
```

Please note that Python does not have direct equivalent of Java's `CompletableFuture` and `Map`. In the above code, I used a dictionary (`dict`) for mapping strings to byte arrays. For asynchronous operations, you can use built-in support in Python with `async/await` syntax or by using libraries like `trio`, `curio`, etc.

Also note that Python does not have direct equivalent of Java's `@Override`. You need to manually override the methods if they are implemented in parent class.