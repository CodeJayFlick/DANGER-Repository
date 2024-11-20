import asyncio
from typing import Dict, List, Set, Any

class DbgModelTargetRegisterContainerImpl:
    def __init__(self, thread: 'DbgThread'):
        self.thread = thread
        self.registers_by_name = {}
        self.values = {}

    async def request_elements(self) -> None:
        registers = await self.thread.list_registers()
        if len(registers) != len(self.registers_by_name):
            for reg in registers:
                await self.thread.delete_model_object(reg)
            self.registers_by_name.clear()

        cached_registers = set(self.registers_by_name.keys())
        new_registers = [self.get_target_register(reg) async for reg in registers]
        self.set_elements(new_registers, {}, "Refreshed")
        if not any(cached_register in (reg.name() for reg in new_registers) 
                   for cached_register in cached_registers):
            await self.read_registers_named(cached_registers)

    def thread_state_changed_specific(self, state: Any, reason: Any) -> None:
        if state != DbgState.RUNNING:
            await self.read_registers_named(set(self.registers_by_name.keys()))

    async def get_target_register(self, register: 'DbgRegister') -> 'DbgModelTargetRegister':
        model_object = await self.thread.get_model_object(register)
        if model_object is not None:
            return model_object
        reg = DbgModelTargetRegisterImpl(self, register)
        self.registers_by_name[register.name()] = reg
        return reg

    async def read_registers_named(self, names: List[str]) -> Dict[str, bytes]:
        result = {}
        for name in names:
            if (reg := self.registers_by_name.get(name)) is not None:
                value = await reg.get_cached_attributes().get(VALUE_ATTRIBUTE_NAME)
                size = reg.size()
                bytes_ = ConversionUtils.bigInteger_to_bytes(size, value)
                result[name] = bytes_
                reg.change_attributes([],
                                       {VALUE_ATTRIBUTE_NAME: str(value).upper()},
                                       "Refreshed")
        self.values = result
        await asyncio.create_task(self.listeners.fire_registers_updated(get_proxy(), result))
        return result

    async def write_registers_named(self, values: Dict[str, bytes]) -> None:
        to_write = {}
        for name, value in values.items():
            reg = self.registers_by_name.get(name)
            if reg is not None:
                val = BigInteger(1, bytearray(value))
                to_write[reg.register()] = val
        await asyncio.create_task(self.thread.write_registers(to_write))
        await asyncio.create_task(self.listeners.fire_registers_updated(get_proxy(), values))

    def get_cached_registers(self) -> Dict[str, bytes]:
        return self.values

class DbgModelTargetRegister:
    pass

class DbgThread:
    async def list_registers(self) -> List['DbgRegister']:
        # todo: implement this method
        raise NotImplementedError()

    async def delete_model_object(self, register: 'DbgRegister') -> None:
        # todo: implement this method
        raise NotImplementedError()

    async def get_model_object(self, register: 'DbgRegister') -> Any:
        # todo: implement this method
        raise NotImplementedError()
