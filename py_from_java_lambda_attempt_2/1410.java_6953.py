Here is the translation of the given Java code into equivalent Python:

```Python
import asyncio
from typing import List, Dict, Any

class GdbModelTargetRegisterContainer:
    NAME = "Registers"

    def __init__(self, inferior: 'GdbInferior') -> None:
        self.impl = inferior.impl
        self.inferior = inferior
        super().__init__()

    async def request_elements(self, refresh: bool) -> Any:
        if not refresh:
            return await asyncio.to_thread(self.inferior.get_known_threads)
        else:
            return await self.do_refresh()

    async def do_refresh(self) -> Any:
        threads = await self.inferior.list_threads
        return await asyncio.create_task(complete_using_threads(threads))

    async def complete_using_threads(self, by_id: Dict[int, 'GdbThread']) -> Any:
        if not by_id:
            set_elements([], "Refreshed (with no thread)")
            return None

        thread = next(iter(by_id.values()))
        registers = await thread.list_registers
        with self.lock:
            self.registers_by_number.clear()
            self.registers_by_number.update({register.get_number(): GdbModelTargetRegister(self, register) for register in registers})

        set_elements(list(registers), "Refreshed")

    def get_target_register(self, register: 'GdbRegister') -> Any:
        return self.registers_by_number.setdefault(register.get_number(), lambda: GdbModelTargetRegister(self, register))()

    async def refresh_internal(self) -> Any:
        try:
            await do_refresh()
        except Exception as ex:
            Msg.error(self, "Problem refreshing inferior's register descriptions", ex)
            return None

    def state_changed(self, sco: 'GdbStateChangeRecord') -> None:
        asyncio.create_task(request_elements(False))
        for model_register in self.registers_by_number.values():
            model_register.state_changed(sco)

class GdbModelTargetRegister:
    # Constructor
    pass

# Other classes and functions are not provided here. You would need to implement them according to your needs.
```

Please note that this is a direct translation of the given Java code into Python, without considering any specific requirements or best practices for Python programming.