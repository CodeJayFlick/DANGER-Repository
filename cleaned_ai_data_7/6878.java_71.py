class DecompilerCallConventionAnalyzer:
    NAME = "Call Convention ID"
    DESCRIPTION = "Uses decompiler to figure out unknown calling conventions."
    
    COULD_NOT_RECOVER_CALLING_CONVENTION = "Could not recover calling convention"
    OPTION_NAME_DECOMPILER_TIMEOUT_SECS = "Analysis Decompiler Timeout (sec)"
    OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS = "Set timeout in seconds for analyzer decompiler calls."

    DEFAULT_DECOMPILER_TIMEOUT_SECS = 60
    DECOMPILER_TIMEOUT_SECONDS_OPTION = DEFAULT_DECOMPILER_TIMEOUT_SECS

    IGNORE_BOOKMARKS = False

    def __init__(self):
        super().__init__(NAME, DESCRIPTION)
        self.set_priority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after().after())
        self.setDefaultEnablement(True)
        self.setSupportsOneTimeAnalysis()

    @staticmethod
    def can_analyze(program: 'Program') -> bool:
        return program.get_language().supports_pcode() and len(program.get_compiler_spec().get_calling_conventions()) > 1

    def register_options(self, options: Options, program: Program):
        options.register_option(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, self.decompiler_timeout_seconds_option,
                                 None, OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS)
        self.options_changed(options, program)

    def options_changed(self, options: Options, program: Program):
        self.decompiler_timeout_seconds_option = options.get_int(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, 
                                                                  self.decompiler_timeout_seconds_option)

    @staticmethod
    async def added(program: 'Program', set: AddressSetView, monitor: TaskMonitor, log: MessageLog) -> None:
        if set.has_same_addresses(program.get_memory()):
            self.IGNORE_BOOKMARKS = True

        try:
            function_entries = await find_locations(program, set, monitor)
            if not function_entries.is_empty():
                run_decompiler_analysis(program, function_entries, monitor)

        except CancelledException as ce:
            raise ce
        except Exception as e:
            Msg.error(self, "Unexpected exception", e)

    @staticmethod
    async def run_decompiler_analysis(program: 'Program', function_entries: AddressSetView, 
                                       monitor: TaskMonitor) -> None:
        decompiler_pool = CachingPool(DecompilerFactory(program))
        callback = ParallelDecompilerCallback(decompiler_pool, program)
        
        queue = ConcurrentGraphQ(callback, graph=AcyclicCallGraphBuilder.build_dependency_graph(
            program, function_entries, True), pool=GThreadPool.get_shared_analsys_threadpool(), 
                                   monitor=monitor)

        try:
            await queue.execute()
        finally:
            if queue is not None:
                queue.dispose()
            decompiler_pool.dispose()

    @staticmethod
    def perform_convention_analysis(function: 'Function', decompiler: DecompInterface, 
                                      monitor: TaskMonitor) -> None:
        cmd = DecompilerParallelConventionAnalysisCmd(function, decompiler, self.decompiler_timeout_seconds_option)
        
        if not await cmd.apply_to(program=function.get_program(), monitor=monitor):
            BookmarkManager(bk_mgr).set_bookmark(
                function.get_entry_point(),
                BookmarkType.WARNING,
                COULD_NOT_RECOVER_CALLING_CONVENTION,
                cmd.status_msg)

    @staticmethod
    async def find_locations(program: 'Program', set: AddressSetView, 
                              monitor: TaskMonitor) -> AddressSet:
        bk_mgr = program.get_bookmark_manager()
        
        function_entries = AddressSet()

        for func in program.get_function_manager().get_functions(set):
            if not await monitor.check_cancelled():
                break

            if self.IGNORE_BOOKMARKS and bk_mgr.get_bookmark(func.get_entry_point(), BookmarkType.WARNING, 
                                                                 COULD_NOT_RECOVER_CALLING_CONVENTION) is not None:
                continue
            
            # Must be a function defined
            if func.is_thunk() or func.is_inline():
                continue

            if func.is_external():
                continue

            if func.has_custom_variable_storage():
                continue

            calling_convention_name = func.get_calling_convention_name()
            
            if not calling_convention_name == Function.UNKNOWN_CALLING_CONVENTION_STRING:
                continue
            
            # Don't touch custom storage
            if has_imported_signature_within_namespace(func) or 
               has_defined_parameter_types(func):
                function_entries.add(func.get_entry_point())

        return function_entries

    @staticmethod
    def has_imported_signature_within_namespace(function: 'Function') -> bool:
        return (function.get_signature_source() == SourceType.IMPORTED and 
                function.get_parent_namespace().get_id() != Namespace.GLOBAL_NAMESPACE_ID)

    @staticmethod
    def has_defined_parameter_types(function: 'Function') -> bool:
        arguments = function.get_signature().get_arguments()
        
        for arg in arguments:
            data_type = arg.data_type
            
            if data_type == DefaultDataType.data_type or Undefined.is_undefined(data_type):
                continue
                
            return True

        return False


class DecompilerFactory(CountingBasicFactory[DecompInterface]):
    def __init__(self, program: 'Program'):
        self.program = program

    async def do_create(self, item_number: int) -> DecompInterface:
        return await DecompilerParallelConventionAnalysisCmd.create_decompiler_interface(program=self.program)

    async def do_dispose(self, decompiler: DecompInterface):
        await decompiler.dispose()


class ParallelDecompilerCallback(QRunnable[Address]):
    def __init__(self, pool: CachingPool[DecompInterface], program: 'Program'):
        self.pool = pool
        self.program = program

    async def run(self, address: Address, monitor: TaskMonitor) -> None:
        if await monitor.check_cancelled():
            return
        
        decompiler = self.pool.get()
        
        try:
            function = self.program.get_function_manager().get_function_at(address)
            
            monitor.set_message(f"{self.__class__.__name__} - decompile {function.name}")
            await perform_convention_analysis(function, decompiler, monitor)

        finally:
            self.pool.release(decompiler)
            monitor.increment_progress(1)


async def main():
    # Create an instance of DecompilerCallConventionAnalyzer
    analyzer = DecompilerCallConventionAnalyzer()

    # Register options for the analyzer
    analyzer.register_options(options=Options(), program='Program')

    try:
        await added(program='Program', set=AddressSetView(), monitor=TaskMonitor(), log=MessageLog())
    except CancelledException as ce:
        raise ce
    except Exception as e:
        Msg.error(analyzer, "Unexpected exception", e)


if __name__ == "__main__":
    import asyncio

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

