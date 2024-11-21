from typing import Dict, List, Any, Tuple

class DbgModelTargetRegisterBank:
    def __init__(self):
        pass

    def get_target_register(self, register: str) -> 'DbgModelTargetRegister':
        # Implement this method as per your requirement.
        return None  # Replace with actual implementation.

    async def read_registers_named(self, names: List[str]) -> Dict[str, bytes]:
        if self.is_waiting():
            print("Cannot process command readRegistersNamed while engine is waiting for events")
            return {}

        result = {}
        for regname in names:
            x = self.get_cached_attributes().get(regname)
            if not isinstance(x, DbgModelTargetRegister):
                continue
            register = (await self.get_register_map(self.path)).get(regname)
            if register is None:
                continue
            map_value = {register: x}
            result.update(map_value)

        return await self.parent_thread().read_registers(set(result.keys()))

    async def write_registers_named(self, values: Dict[str, bytes]) -> Tuple[None]:
        thread = self.parent_thread()
        request_native_elements().handle(next_ignore)
        regset = (await thread.list_registers())
        to_write = {}
        for ent in values.items():
            regname = ent.key
            x = self.get_cached_attributes().get(regname)
            if not isinstance(x, DbgModelTargetRegister):
                raise DebuggerRegisterAccessException(f"No such register: {regname}")
            val = bytes_to_big_integer(ent.value)
            dbgreg = regset[regname]
            to_write.update({dbgreg: val})

        await thread.write_registers(to_write)

    def get_cached_registers(self) -> Dict[str, bytes]:
        return self.get_values()

    def get_values(self) -> Dict[str, Any]:
        result = {}
        for entry in self.get_cached_attributes().items():
            if isinstance(entry.value, DbgModelTargetRegister):
                reg = entry.value
                bytes_ = reg.get_bytes()
                result.update({entry.key: bytes})

        return result

    def is_waiting(self) -> bool:
        # Implement this method as per your requirement.
        return False  # Replace with actual implementation.

    async def get_register_map(self, path: str) -> Dict[str, Any]:
        # Implement this method as per your requirement.
        return {}

    async def parent_thread(self) -> 'DbgThread':
        # Implement this method as per your requirement.
        return None  # Replace with actual implementation.

def bytes_to_big_integer(bytes_: bytes) -> int:
    pass

class DbgModelTargetRegister:
    def __init__(self):
        pass

    @property
    def cached_attributes(self) -> Dict[str, Any]:
        # Implement this method as per your requirement.
        return {}

    def get_bytes(self) -> bytes:
        # Implement this method as per your requirement.
        return None  # Replace with actual implementation.

class DbgThread:
    pass

class DebuggerRegisterAccessException(Exception):
    pass
