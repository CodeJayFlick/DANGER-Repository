import ghidra.app.cmd.function.CreateFunctionCmd
from ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd import ClearFlowAndRepairCmd
from ghidra.program.model.address import AddressSetView, Address
from ghidra.program.model.block import CodeBlockReferenceIterator, CodeBlock
from ghidra.program.model.flow import FlowType
from ghidra.util.exception import CancelledException

class FixupNoReturnFunctionsScript:
    def __init__(self):
        self.entry_list = None

    @Override
    public void run() throws Exception {
        program = current_program
        table_executor = create_table_executor()
        
        if is_running_headless():
            entry_list = IssueEntryList()
        else:
            table_dialog = TableChooserDialog("Suspect Non-Returning Functions", executor)
            configure_table_columns(table_dialog)
            table_dialog.show()
            table_dialog.set_message("Searching...")
            entry_list = TableEntryList(table_dialog)

        detect_no_return(program, entry_list)

        if is_running_headless():
            for i in range(entry_list.get_num_entries()):
                no_return_locations = entry_list.get_entry(i)
                if not no_return_locations.is_fixed():
                    executor.execute(no_return_locations)
