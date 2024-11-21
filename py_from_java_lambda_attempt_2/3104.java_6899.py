Here is the translation of the Java code into Python:

```Python
import os
from ghidra_script import GhidraScript


class ResolveX86orX64LinuxSyscallsScript(GhidraScript):
    def __init__(self):
        self.x86_bytes = bytes([0x65, -1, 0x15, 0x10, 0x00, 0x00, 0x00])
        self.X86 = "x86"
        self.SYSCALL_SPACE_NAME = "syscall"
        self.SYSCALL_SPACE_LENGTH = 0x10000
        self.SYSCALL_X64_CALLOTHER = "syscall"

    def run(self):
        if not (self.current_program.get_executable_format().equals("ELF_32") or 
                self.current_program.get_language().get_processor().toString() == self.X86):
            popup("This script is intended for x86 or x64 Linux files")
            return

        size = self.current_program.get_language().get_language_description().size
        if size == 64:
            self.tester = ResolveX86orX64LinuxSyscallsScript.check_x64_instruction
            self.syscall_register = "RAX"
            self.datatype_archive_name = "generic_64"
            selfsyscall_file_name = "x64_linux_syscall_numbers"
            self.override_type = RefType.CALLOTHER_OVERRIDE_CALL
            self.calling_convention = "syscall"

        else:
            self.tester = ResolveX86orX64LinuxSyscallsScript.check_x86_instruction
            self.syscall_register = "EAX"
            self.datatype_archive_name = "generic_32"
            selfsyscall_file_name = "x86_linux_syscall_numbers"
            self.override_type = RefType.CALL_OVERRIDE_UNCONDITIONAL
            self.calling_convention = "syscall"

        syscall_space = None

        if size == 64:
            syscall_space = AddressSpace(self.SYSCALL_SPACE_NAME)
        else:
            syscall_space = current_program.get_address_factory().get_address_space(
                BasicCompilerSpec.OTHER_SPACE_NAME)

        if syscall_space is None:
            popup("Must have exclusive access to " + self.current_program.name +
                  " to run this script")
            return

        funcs_to_calls = get_syscalls_in_functions(self.current_program, monitor)
        addresses_to_syscalls = resolve_constants(funcs_to_calls, self.current_program, monitor)

        if not addresses_to_syscalls:
            popup("Couldn't resolve any syscall constants")
            return

        syscall_numbers_to_names = getsyscall_number_map()

        for entry in addresses_to_syscalls.items():
            call_site = entry[0]
            offset = entry[1]
            call_target = syscall_space.get_address(offset)
            callee = self.current_program.function_manager.get_function_at(call_target)

            if callee is None:
                func_name = "syscall_" + str(format("%08X", offset))
                if syscall_numbers_to_names.get(offset) is not None:
                    func_name = syscall_numbers_to_names[offset]
                callee = create_function(call_target, func_name)
                callee.set_calling_convention(self.calling_convention)

            ref = self.current_program.reference_manager.add_memory_reference(
                call_site, call_target, self.override_type, SourceType.USER_DEFINED, Reference.MNEMONIC
            )
            self.current_program.reference_manager.set_primary(ref, True)

        auto_analysis_manager = AutoAnalysisManager.get_analysis_manager(self.current_program)
        data_type_managers = [auto_analysis_manager.data_type_manager_service.open_data_type_archive(
            self.datatype_archive_name), self.current_program.data_type_manager]
        apply_function_data_types_cmd = ApplyFunctionDataTypesCmd(data_type_managers, AddressSet(
            syscall_space.min_address(), syscall_space.max_address()), SourceType.USER_DEFINED, False, False)
        apply_function_data_types_cmd.apply_to(self.current_program)

    def getsyscall_number_map(self):
        syscall_map = {}
        resource_file = Application.find_data_file_in_any_module(self.syscall_file_name)
        if resource_file is None:
            popup("Error opening syscall number file, using default names")
            return syscall_map

        try:
            with open(resource_file.get_file(False), 'r') as f_reader:
                bufferedReader = BufferedReader(f_reader)

                line = None
                while (line := bufferedReader.readline()) is not None:
                    if not line.startswith("#"):
                        parts = line.strip().split("  ")
                        number = int(parts[0], 16)
                        syscall_map[number] = parts[1]

        except IOException as e:
            Msg.show_error(self, None, "Error reading syscall map file", e.get_message(), e)

        return syscall_map

    def get_syscalls_in_functions(self, program):
        funcs_to_calls = {}
        for func in program.function_manager.get_functions_no_stubs(True):
            monitor.check_canceled()
            for inst in program.listing().get_instructions(func.body(), True):
                if self.tester(inst):
                    call_sites = funcs_to_calls.get(func)
                    if call_sites is None:
                        call_sites = set()
                        funcs_to_calls[func] = call_sites
                    call_sites.add(inst.address)

        return funcs_to_calls

    def resolve_constants(self, funcs_to_calls, program, monitor):
        addresses_to_syscalls = {}
        syscall_reg = program.language.get_register(self.syscall_register)
        for func in funcs_to_calls:
            start = func.entry_point()
            context_evaluator = ConstantPropagationContextEvaluator(True)
            symbolic_propagator = SymbolicPropagator(program)

            try:
                symbolic_propagator.flow_constants(start, func.body(), context_evaluator, True, monitor)
            except CancelledException as e:
                Msg.show_error(self, None, "Error resolving syscall constants", str(e), e)

        return addresses_to_syscalls

    @staticmethod
    def check_x86_instruction(inst):
        try:
            return bytes([0x65, -1, 0x15, 0x10, 0x00, 0x00, 0x00]) == inst.get_bytes()
        except MemoryAccessException as e:
            Msg.info(ResolveX86orX64LinuxSyscallsScript, "MemoryAccessException at " + str(inst.address))
            return False

    @staticmethod
    def check_x64_instruction(inst):
        for pcode_op in inst.pcode():
            if pcode_op.get_opcode() == PcodeOp.CALLOTHER:
                index = int(pcode_op.input(0).get_offset())
                if inst.program.language.user_defined_op_name(index) == ResolveX86orX64LinuxSyscallsScript.SYSCALL_X64_CALLOTHER:
                    return True
        return False


class GhidraScript:
    def __init__(self):
        self.current_program = None

    @property
    def current_program(self):
        return self._current_program

    @current_program.setter
    def current_program(self, value):
        self._current_program = value