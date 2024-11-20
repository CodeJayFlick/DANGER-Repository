Here is the translation of the given Java code into Python:

```Python
class ArmDisassemblyInject:
    THUMB_BIT = 0x20

    def is_thumb_mode(self, cpsr):
        return (cpsr & self.THUMB_BIT) != 0

    def pre(self, tool, command, view, thread, start_set, restricted):
        # TODO: There are probably several avenues to figure the TMode. The most important,
        # I think is the cpsr register, when it's available.
        
        try:
            cpsr_reg = view.get_register("cpsr")
            t_mode_reg = view.get_register("TMode")

            if cpsr_reg is None or t_mode_reg is None:
                print(f"No cpsr or TMode register in ARM language?: {view.language_id}")
                return

            regs = thread.memory_manager.get_memory_registerspace(thread, False)

            # Some variants (particularly Cortex-M) are missing cpsr This seems to indicate it only
            # supports THUMB. There is an epsr (xpsr in gdb), but we don't have it in our models,
            # and its TMode bit must be set, or it will fault.
            
            if regs is None or view.get_snap().get_state(regs) != "KNOWN":
                command.set_initial_context(t_mode_reg, 1)
                return

            cpsr_val = thread.memory_manager.get_value(view.get_snap(), cpsr_reg)

            if self.is_thumb_mode(cpsr_val):
                command.set_initial_context(t_mode_reg, 1)
            else:
                command.set_initial_context(t_mode_reg, 0)
        except Exception as e:
            print(f"Error: {e}")
```

Please note that Python does not have direct equivalent of Java's `@DisassemblyInjectInfo` annotation. Also, the code assumes some classes and methods (`PluginTool`, `DisassembleCommand`, etc.) which are specific to Ghidra framework and may need additional setup or imports in a standalone Python environment.