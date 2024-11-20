class DefaultDebuggerTargetTraceMapper:
    def __init__(self, target: 'TargetObject', lang_id: str, cs_id: str, extra_reg_names: list):
        self.target = target
        self.language = get_language(lang_id)
        self.c_spec = self.language.get_compiler_spec_by_id(cs_id)

        self.extra_reg_names = set(extra_reg_names[:])

    def create_memory_mapper(self, memory: 'TargetMemory') -> dict:
        return {'language': self.language, 'model': memory.model}

    def create_register_mapper(self, registers: 'TargetRegisterContainer') -> dict:
        return {'c_spec': self.c_spec, 'registers': registers, 'sync': False}

    async def offer_memory(self, memory: 'TargetMemory'):
        mm = self.create_memory_mapper(memory)
        await asyncio.sleep(0)  # This is equivalent to CompletableFuture.completedFuture
        return mm

    async def offer_registers(self, registers: 'TargetRegisterContainer'):
        rm = self.create_register_mapper(registers)
        await asyncio.sleep(0)  # This is equivalent to CompletableFuture.completedFuture
        return rm

    @property
    def extra_reg_names(self):
        return self.extra_reg_names.copy()

    def get_trace_language(self):
        return self.language

    def get_trace_compiler_spec(self):
        return self.c_spec

    async def start_recording(self, service: 'DebuggerModelServicePlugin', trace: dict) -> dict:
        return {'service': service, 'trace': trace, 'target': self.target, 'mapper': self}

def get_language(lang_id: str):
    # This function is not implemented in the given Java code
    pass

class TargetObject:
    def __init__(self):
        pass

class Language:
    def __init__(self):
        pass

    def get_compiler_spec_by_id(self, cs_id: str) -> dict:
        return {}

class CompilerSpec:
    def __init__(self):
        pass

async def main():
    target = TargetObject()
    lang_id = 'lang_id'
    cs_id = 'cs_id'
    extra_reg_names = ['reg1', 'reg2']
    
    mapper = DefaultDebuggerTargetTraceMapper(target, lang_id, cs_id, extra_reg_names)

    memory = await mapper.offer_memory(TargetMemory())
    registers = await mapper.offer_registers(TargetRegisterContainer())

if __name__ == "__main__":
    import asyncio
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
