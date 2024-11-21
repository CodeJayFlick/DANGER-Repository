Here is the translation of the given Java code into Python:

```Python
import ghidra.app.script.GhidraScript
from ghidra.program.model.address import AddressSetView
from ghidra.program.model.symbol import ReferenceIterator
from ghidra.program.model.data import BookmarkManager, BookmarkType

class FindSharedReturnFunctionsScript(GhidraScript):
    def run(self) -> None:
        program = self.currentProgram
        
        table_dialog = create_table_chooser_dialog("Suspect Shared-Return Jump to Functions")
        configure_table_columns(table_dialog)
        
        set = detect_shared_return(program, table_dialog)
        
        table_dialog.set_message("Choose entries to be made Shared-Return Jump Locations")

    def configure_table_columns(self, table_dialog: TableChooserDialog) -> None:
        explanation_column = StringColumnDisplay()
        explanation_column.column_name = "Explanation"
        explanation_column.get_column_value = lambda row_object: get_explanation(row_object)
        
        func_column = StringColumnDisplay()
        func_column.column_name = "Shared Return Func"
        func_column.get_column_value = lambda row_object: get_shared_return_func(row_object)

        jump_from_column = StringColumnDisplay()
        jump_from_column.column_name = "Jump From Func"
        jump_from_column.get_column_value = lambda row_object: get_jump_from_func(row_object)
        
        status_column = StringColumnDisplay()
        status_column.column_name = "Status"
        status_column.get_column_value = lambda row_object: get_status(row_object)

        table_dialog.add_custom_column(explanation_column)
        table_dialog.add_custom_column(func_column)
        table_dialog.add_custom_column(jump_from_column)
        table_dialog.add_custom_column(status_column)

    def create_table_executor(self) -> TableChooserExecutor:
        executor = TableChooserExecutor()
        executor.get_button_name = lambda: "Fixup SharedReturn"
        
        def execute(row_object):
            shared_ret_loc = row_object
            print(f"Fixup Shared Return Jump at : {row_object.address}")
            
            program = shared_ret_loc.program
            entry_address = shared_ret_loc.address
            
            add_bookmark(program, entry_address, "Shared Return Jump")
            
            if not shared_ret_loc.status == "fixed":
                fix_shared_return_location(program, entry_address)
                
            add_bookmark(program, shared_ret_loc.why_addr, shared_ret_loc.explanation)
            return False
        
        executor.execute = execute
        return executor

    def detect_shared_return(self, program: Program, table_dialog: TableChooserDialog) -> AddressSet:
        set = AddressSet()
        
        for function in program.function_manager.get_functions(True):
            entry_address = function.entry_point
            
            # Get all References to the function
            ref_iter = program.reference_manager.get_references_to(entry_address)
            
            while ref_iter.has_next():
                ref = ref_iter.next()
                
                if ref.reference_type == ReferenceType.CALL:
                    continue
                
        body_view = function.body
        
        ref_iter = program.reference_manager.get_references_to(entry_address)
        
        while ref_iter.has_next():
            ref = ref_iter.next()
            
            if not ref.reference_type == ReferenceType.JUMP:
                continue
            
            # jumps to the top of this function, don't count
            if body_view.contains(ref.from_address):
                continue
                
            jump_from_addr = ref.from_address
            
            location = SharedReturnLocations(program, jump_from_addr, entry_address, "Jumps to called location")
            
            table_dialog.add(location)
            
            set.add_range(entry_address, entry_address)

        return set

    def add_bookmark(self, program: Program, address: Address, message: str) -> None:
        bookmark_manager = program.bookmark_manager
        
        if not bookmark_manager.get_bookmark(address, BookmarkType.NOTE, "FixupSharedReturnFunctions Script"):
            bookmark_manager.set_bookmark(address, BookmarkType.NOTE, "FixupSharedReturnFunctions Script", message)

class TableChooserExecutor:
    def get_button_name(self) -> str:
        return "Fixup SharedReturn"

    def execute(self, row_object: AddressableRowObject) -> bool:
        pass

class StringColumnDisplay:
    def __init__(self):
        self.column_name = ""
        
    def get_column_value(self, row_object: AddressableRowObject) -> str:
        pass

def create_table_chooser_dialog(title: str) -> TableChooserDialog:
    return None

def configure_table_columns(table_dialog: TableChooserDialog) -> None:
    pass

class SharedReturnLocations(AddressableRowObject):
    def __init__(self, program: Program, address: Address, why_addr: Address, explanation: str):
        self.program = program
        self.address = address
        self.why_addr = why_addr
        self.explanation = explanation
        
    def get_program(self) -> Program:
        return self.program

    def get_address(self) -> Address:
        return self.address

def detect_shared_return(program: Program, table_dialog: TableChooserDialog) -> AddressSet:
    pass