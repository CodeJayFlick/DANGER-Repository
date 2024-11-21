import logging

class DecompilerParallelConventionAnalysisCmd:
    STD_NAMESPACE = "std"

    def __init__(self, func, decompiler_interface, decompiler_timeout_secs):
        self.function = func
        self.decompiler = decompiler_interface
        self.decompiler_timeout_secs = decompiler_timeout_secs
        super().__init__("Identify Calling Convention", True, True, False)

    @staticmethod
    def create_decompiler_interface(program) -> 'DecompilerInterface':
        new_interface = DecompilerInterface()
        new_interface.toggle_c_code(False)
        new_interface.toggle_syntax_tree(False)  # only recovering the calling convention, no syntax tree needed
        new_interface.set_simplification_style("paramid")

        opts = DecompileOptions()
        opts.eliminate_unreachable(False)
        opts.grab_from_program(program)
        new_interface.set_options(opts)

        if not new_interface.open_program(program):
            raise IOException(f"Unable to create decompiler for program: {program}")

        return new_interface

    def apply_to(self, obj, monitor) -> bool:
        self.program = Program(obj)

        try:
            monitor.check_cancelled()

            monitor.set_message("Decompile " + self.function.name)
            status_msg = None
            analyze_function(self.function, monitor)
            if status_msg and len(status_msg):
                return False

        except CancelledException as e:
            # just drop out
            pass

        except Exception as e:
            logging.error(e.message)
            status_msg = str(e)

        finally:
            self.program.set_signature_source(SourceType.DEFAULT)

    def func_is_external_glue(self, function) -> bool:
        block_name = self.program.memory.get_block(function.entry_point).name
        return (block_name == MemoryBlock.EXTERNAL_BLOCK_NAME or 
                block_name == ".plt" or 
                block_name == "__stub_helper")

    @staticmethod
    def is_in_std_namespace(function) -> bool:
        parent_namespace = function.parent_namespace
        return parent_namespace.name == DecompilerParallelConventionAnalysisCmd.STD_NAMESPACE and \
               parent_namespace.get_parent_namespace().get_id() == Namespace.GLOBAL_NAMESPACE_ID

    def analyze_function(self, f, monitor):
        if not f or f.is_thunk() or self.is_in_std_namespace(f):
            return

        # if custom storage already enabled or calling convention known, return
        if f.has_custom_variable_storage() or \
           not f.get_calling_convention_name().equals(Function.UNKNOWN_CALLING_CONVENTION_STRING):
            return

        # We didn't "wipe" previous results of external functions, but we also do not want to set new results.
        if f.is_external():
            return

        if self.func_is_external_glue(f):
            return

        signature_source = f.get_signature_source()

        try:
            decomp_res = None
            if monitor.is_cancelled():
                return

            # reset the sourcetype so that no signature information goes to the decompiler
            #   we will set it back later.
            f.set_signature_source(SourceType.DEFAULT)

            decomp_res = self.decompiler.decompile_function(f, self.decompiler_timeout_secs, monitor)
            status_msg = str(decomp_res.get_error_message())

            if monitor.is_cancelled():
                return

            if not decomp_res.decompile_completed():
                return

            high_function = decomp_res.get_high_function()
            model_name = high_function.function_prototype.model_name

            # TODO: Need to check the calling convention name
            #      what does decompiler return if it doesn't know convention, or guessed?
            if not model_name.equals(Function.DEFAULT_CALLING_CONVENTION_STRING):
                signature_source = self.update_calling_convention(f, signature_source, high_function, model_name)

        except Exception as e:
            logging.error(str(e))

    def update_calling_convention(self, f, signature_source, high_function, model_name) -> SourceType:
        parent_namespace = f.parent_namespace
        if f.parameter_count + 1 == high_function.function_prototype.num_params:
            # does it have a namespace
            if parent_namespace.get_id() != Namespace.GLOBAL_NAMESPACE_ID and \
               not parent_namespace.name.equals(self.STD_NAMESPACE):
                #    does it have a this call convention that is the equivalent of the stdcall
                calling_convention = self.program.compiler_spec.get_calling_convention(CompilerSpec.CALLING_CONVENTION_thiscall)
                if calling_convection:
                    model_name = CompilerSpec.CALLING_CONVENTION_thiscall

        #   Then is __thiscall, create an object and new parameter if it doesn't have one yet.
        if model_name.equals(CompilerSpec.CALLING_CONVENTION_stdcall) and \
           f.stack_purge_size == 0 and f.parameter_count > 0:
            # if has parameters, and there is no purge, it can't be a stdcall, change it to cdecl
            if self.program.language_id.id_as_string.startswith("x86:LE:32"):
                model_name = CompilerSpec.CALLING_CONVENTION_cdecl

        if parent_namespace.symbol.get_symbol_type() == SymbolType.NAMESPACE and \
           model_name.equals(CompilerSpec.CALLING_CONVENTION_thiscall):
            NamespaceUtils.convert_namespace_to_class(f.parent_namespace)

        f.set_calling_convention(model_name)
        if signature_source == SourceType.DEFAULT:
            signature_source = SourceType.ANALYSIS

        return signature_source
