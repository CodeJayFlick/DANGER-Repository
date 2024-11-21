Here is a translation of the Java code into equivalent Python:

```Python
class DisassemblerPlugin:
    def __init__(self):
        self.create_actions()

    @staticmethod
    def get_description():
        return "Provides disassembler services for all supplied machine language modules."

    @staticmethod
    def get_descriptive_name():
        return "Disassembler"

    @staticmethod
    def get_category():
        return "Disassemblers"

    def create_actions(self):
        pass  # This method is not implemented in Python

    def process_event(self, event):
        if isinstance(event, ProgramActivatedPluginEvent):
            self.program_activated((event).get_active_program())

    def program_activated(self, program):
        options = program.get_options()
        options.register_option("MARK_BAD_INSTRUCTION_PROPERTY", True, None,
                                 "Place ERROR Bookmark at locations where disassembly could not be performed.")
        options.register_option("MARK_UNIMPL_PCODE_PROPERTY", True, None,
                                 "Place WARNING Bookmark at locations where a disassembled instruction has unimplemented pcode.")
        options.register_option(
            "RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY",
            False,
            None,
            "Restrict disassembly to executable memory blocks."
        )

    def set_flow_override_action(self, context):
        pass  # This method is not implemented in Python

    def check_disassembly_enabled(self, context, address, follow_ptr):
        if (context.get_selection() and
                len(context.get_selection()) > 0):
            return True

        listing = context.get_program().get_listing()
        instruction = listing.get_instruction_containing(address)
        data = listing.get_defined_data_containing(address)

        if not (instruction or data) and address in context.get_program().get_memory():
            return False
        elif follow_ptr:
            ptr_addr = data[0].address
            if ptr_addr is not None:
                return self.check_disassembly_enabled(context, ptr_addr, False)
        else:
            return True

    def set_default_context(self, context):
        pass  # This method is not implemented in Python

    def has_context_registers(self, program):
        base_context_reg = program.get_language().get_context_base_register()
        if (base_context_reg and
                len(base_context_reg.children) > 0):
            return True
        else:
            return False

    def disassemble_arm_callback(self, context, thumb_mode):
        pass  # This method is not implemented in Python

    def disassemble_hcs12_callback(self, context, xg_mode):
        pass  # This method is not implemented in Python

    def disassemble_mips_callback(self, context, mips16_mode):
        pass  # This method is not implemented in Python

    def disassemble_ppc_callback(self, context, vle_mode):
        pass  # This method is not implemented in Python

    def disassemble_x86_64_callback(self, context, size32_mode):
        pass  # This method is not implemented in Python
```

Note that the `create_actions`, `disassemble_arm_callback`, `disassemble_hcs12_callback`, `disassemble_mips_callback`, `disassemble_ppc_callback`, and `disassemble_x86_64_callback` methods are not implemented as they were not provided with their implementation.