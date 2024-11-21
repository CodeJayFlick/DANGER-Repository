import threading

class DecompilerParameterIdCmd:
    def __init__(self, name, entries, source_type_clear_level, commit_data_types, 
                 commit_void_return, decompiler_timeout_secs):
        self.entry_points = set(entries)
        self.program = None
        self.source_type_clear_level = source_type_clear_level
        self.commit_data_types = commit_data_types
        self.commit_void_return = commit_void_return
        self.decompiler_timeout_secs = decompiler_timeout_secs

    def apply_to(self, obj):
        self.program = obj
        try:
            monitor = TaskMonitor()
            monitor.set_message(f"{self.name} - creating dependency graph...")
            builder = AcyclicCallGraphBuilder(self.program, self.entry_points)
            graph = builder.get_dependency_graph(monitor)
            if not graph:
                return True

            pool = AutoAnalysisManager().get_shared_analsys_thread_pool()
            queue = ConcurrentGraphQ(graph, pool, monitor)

            reset_function_source_types(graph.values(), monitor)

            monitor.set_message(f"{self.name} - analyzing...")
            monitor.initialize(len(graph))
            queue.execute()

        except CancelledException:
            pass
        except Exception as e:
            self.status_msg(str(e))
            return False

        finally:
            if queue is not None:
                queue.dispose()
            pool.dispose()

        return True

    def func_is_external_glue(self, function):
        block_name = self.program.get_memory().get_block(function.entry_point).name
        return (block_name == "EXTERNAL_BLOCK_NAME" or 
               block_name == ".plt" or 
               block_name == "__stub_helper")

    def reset_function_source_types(self, addresses, monitor):
        try:
            function_manager = self.program.function_manager()
            for address in addresses:
                if not monitor.is_cancelled():
                    monitor.check_cancelled()
                    monitor.increment_progress(1)

                function = function_manager.get_function_at(address)
                if function is None or function.is_external() or self.func_is_external_glue(function):
                    continue

                parameter = function.return_
                if parameter and not parameter.source().is_higher_priority_than(self.source_type_clear_level):
                    function.set_return(parameter.data_type, 
                                         parameter.variable_storage(), SourceType.DEFAULT)

            monitor.check_cancelled()
        except InvalidInputException as e:
            self.status_msg(f"Error changing signature source type on {function.name}: {e}")

    def analyze_function(self, decompiler, function, monitor):
        if not (function and not function.is_thunk() and 
                function.signature_source != SourceType.DEFAULT):
            return

        try:
            results = decompiler.decompile_function(function, self.decompiler_timeout_secs, monitor)
            status_msg = str(results.error_message) if results else ""
            self.status_msg(f"Failed to decompile function: {function.name} {status_msg}")

        except Exception as e:
            self.status_msg(str(e))

    def has_inconsistent_results(self, decomp_res):
        high_function = decomp_res.high_function
        if not (high_function and 
                isinstance(high_function.local_symbol_map().symbols(), list)):
            return False

        for symbol in high_function.local_symbol_map().symbols():
            if not isinstance(symbol.get_high_variable(), HighLocal) or \
               not symbol.name.startswith("in_"):
                continue

            function = high_function.function
            if function and function.entry_point:
                bookmark_manager = function.program.bookmark_manager()
                bookmark_manager.set_bookmark(
                    function.entry_point, BookmarkType.WARNING,
                    "DecompilerParamID", f"Problem recovering parameters in function {function.name} at {function.entry_point}")

        return True

    def check_model_name_consistency(self, function):
        if not (isinstance(function.parameters(), list) and 
                len(function.parameters()) > 0 and 
                function.calling_convention_name == CompilerSpec.CALLING_CONVENTION_stdcall):
            try:
                function.set_calling_convention(CompilerSpec.CALLING_CONVENTION_cdecl)
            except InvalidInputException as e:
                self.status_msg(f"Invalid Calling Convention {CompilerSpec.CALLING_CONVENTION_cdecl}: {e}")

    class DecompilerFactory(threading.Thread):
        def __init__(self, decompiler_pool):
            super().__init__()
            self.decomposer = None
            self.pool = decompiler_pool

        def run(self):
            try:
                self.decomposer = self.pool.get()
                if not (isinstance(self.decomposer, DecompInterface) and 
                        isinstance(self.decomposer.options(), DecompileOptions)):
                    raise Exception("Invalid Decompiler")
            finally:
                if self.decomposer is not None:
                    self.pool.release(self.decomposer)

        def do_dispose(self):
            if self.decomposer is not None:
                self.decomposer.dispose()

    class ParallelDecompileRunnable(threading.Thread):
        def __init__(self, decompiler_pool):
            super().__init__()
            self.pool = decompiler_pool

        def run(self, address, monitor):
            try:
                function = self.program.function_manager().get_function_at(address)
                do_work(function, self.decomposer, monitor)

            except CancelledException as e:
                pass
            except Exception as e:
                self.status_msg(str(e))

        def do_work(self, function, decompiler, monitor):
            if not (isinstance(decompiler, DecompInterface) and 
                    isinstance(monitor, TaskMonitor)):
                raise Exception("Invalid Decompile Options")

            try:
                analyze_function(decomposer, function, monitor)
            finally:
                self.pool.release(decomposer)

    def __init__(self, name="DecompilerParameterIdCmd"):
        super().__init__()
        self.name = name

# Usage
cmd = DecompilerParameterIdCmd("My Decompiler", [0x10000000], SourceType.ANALYSIS,
                                 True, False, 60)
program = Program()
try:
    cmd.apply_to(program)
except Exception as e:
    print(f"Error: {e}")
