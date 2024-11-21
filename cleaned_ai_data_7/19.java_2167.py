import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import AddressSpace
from ghidra.util.database import UndoableTransaction
from ghidra.trace.model import DefaultTraceLocation, Trace

class AddMapping(GhidraScript):
    def run(self) -> None:
        mappings = self.state.getTool().getService("DebuggerStaticMappingService")
        traces = self.state.getTool().getService("DebuggerTraceManagerService")
        current_trace = traces.getCurrentTrace()
        dyn_ram = AddressSpace(current_trace.getBaseAddressFactory().getDefaultAddressSpace())
        stat_ram = self.current_program.getAddressFactory().getDefaultAddressSpace()

        try:
            with UndoableTransaction.start(self.current_trace, "Add Mapping", True) as tid:
                mappings.add_mapping(
                    DefaultTraceLocation(current_trace, None, Range.at_least(0), dyn_ram.get_address(0x00400000)),
                    ProgramLocation(self.current_program, stat_ram.get_address(0x00400000)), 0x10000, False)
        except Exception as e:
            print(f"An error occurred: {e}")
