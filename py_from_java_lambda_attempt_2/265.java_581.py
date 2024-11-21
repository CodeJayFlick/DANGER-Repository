Here is your Java code translated into equivalent Python:

```Python
class DefaultThreadRecorder:
    def __init__(self, recorder: 'DefaultTraceRecorder', mapper: 'DefaultDebuggerTargetTraceMapper',
                 target_thread: 'TargetThread', trace_thread: 'TraceThread'):
        self.recorder = recorder
        self.mapper = mapper
        self.trace = recorder.get_trace()
        self.object_manager = recorder.get_object_manager()

        self.target_thread = target_thread
        self.trace_thread = trace_thread

        self.memory_manager = self.trace.get_memory_manager()

    def init_reg_mapper(self, registers: 'TargetRegisterContainer') -> CompletableFuture['Void']:
        return self.object_manager.get_reg_mappers().get(registers).then_accept(
            lambda rm: (synchronized(self): 
                self.reg_mapper = rm
                language = self.trace.get_base_language()
                extra_regs = set()
                for rn in self.mapper.get_extra_reg_names():
                    trace_reg = language.get_register(rn)
                    if trace_reg is None:
                        Msg.error(self, f"Mapper's extra register '{rn}' is not in the language!")
                        continue
                    target_reg = rm.trace_to_target(trace_reg)
                    if target_reg is None:
                        Msg.error(self, f"Mapper's extra register '{trace_reg}' is not mappable!")
                        continue
                    extra_regs.add(target_reg)

    def do_fetch_and_init_reg_mapper(self, bank: 'TargetRegisterBank') -> CompletableFuture['Void']:
        return self.init_reg_mapper(bank).then_accept(
            lambda __: (self.recorder.get_listeners().fire_register_bank_mapped(self)))

    def capture_thread_registers(self, thread: 'TraceThread', frame_level: int,
                                  registers: set) -> CompletableFuture[Map['Register', RegisterValue]]:
        if self.reg_mapper is None:
            raise IllegalStateException(f"Have not found register descriptions for {thread}")
        if not all(reg in self.reg_mapper.get_registers_on_target() for reg in registers):
            raise ValueError("All given registers must be recognized by the target")
        t_regs = [self.reg_mapper.trace_to_target(reg) for reg in registers]
        bank = self.get_target_register_bank(thread, frame_level)
        return bank.read_registers(t_regs).then_map(
            lambda values: dict(zip([reg.name for reg in registers], values)))

    def get_target_register_bank(self, thread: 'TraceThread', frame_level: int):
        return {frame_level}

    # ... other methods ...
```

Note that this translation is not perfect and may require some adjustments to work correctly.