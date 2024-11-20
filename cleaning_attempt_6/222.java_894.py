class DbgengX64DisassemblyInject:
    class Mode(enum.Enum):
        X64 = 1
        X86 = 2
        UNK = 3

    def pre(self, tool: 'PluginTool', command: 'DisassembleCommand', view: 'TraceProgramView',
            thread: 'TraceThread', start_set: 'AddressSetView', restricted: 'AddressSetView'):
        trace = view.get_trace()
        first_range = start_set.get_first_range()
        if not first_range:
            return
        model_service = tool.get_service(DebuggerModelService)
        recorder = model_service.get_recorder(trace) if model_service else None
        modules = [module for module in trace.get_module_manager().get_modules_at(view.get_snap(), first_range.min_address)]
        modes = set()
        for m in modules:
            mode = self.mode_for_module(recorder, view, m)
            if mode is not Mode.UNK:
                modes.add(mode)
        if len(modes) != 1:
            return
        mode = next(iter(modes))
        lang = trace.get_base_language()
        addrsize_reg = lang.get_register("addrsize")
        opsize_reg = lang.get_register("opsize")
        context = ProgramContextImpl(lang)
        lang.apply_context_settings(context)
        ctx_val = context.get_disassembly_context(first_range.min_address)
        if mode == Mode.X64:
            command.set_initial_context(ctx_val.assign(addrsize_reg, 2).assign(opsize_reg, 2))
        elif mode == Mode.X86:
            command.set_initial_context(ctx_val.assign(addrsize_reg, 1).assign(opsize_reg, 1))

    def mode_for_module(self, recorder: 'TraceRecorder', view: 'TraceProgramView',
                         module: 'TraceModule'):
        if recorder and recorder.get_snap() == view.get_snap():
            set = AddressSet()
            set.add(module.get_base(), module.get_base())
            try:
                recorder.capture_process_memory(set, TaskMonitor.DUMMY, False).get(1000)
            except (InterruptedException, ExecutionException, TimeoutException) as e:
                Msg.error("Could not read module header from target", e)
        mbp = MemoryByteProvider(view.get_memory(), module.get_base())
        try:
            pe = PortableExecutable.create_portable_executable(
                RethrowContinuesFactory.INSTANCE, mbp, SectionLayout.MEMORY, False, False
            )
            nt_header = pe.get_nt_header()
            if not nt_header:
                return Mode.UNK
            optional_header = nt_header.get_optional_header()
            if not optional_header:
                return Mode.UNK  # Really shouldn't happen, but who knows?
            return Mode.X64 if optional_header.is_64bit() else Mode.X86
        except IOException as e:
            Msg.warn(self, "Could not parse PE from trace: {}".format(e))
            return Mode.UNK

class ProgramContextImpl:
    def __init__(self, lang):
        self.lang = lang

    def get_disassembly_context(self, address):
        pass  # Not implemented in Python
