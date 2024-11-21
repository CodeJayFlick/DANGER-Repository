import ghidra.app.script.GhidraScript
from ghidra.program.model.listing import FunctionIterator, Function
from ghidra.program.model.mem import ReferenceManager

class ClearOrphanFunctions(GhidraScript):
    def run(self) -> None:
        func_iter = self.current_program.get_listing().get_functions(True)
        while func_iter.hasNext():
            func = func_iter.next()
            if self.current_program.reference_manager.get_reference_count_to(func.get_entry_point()) == 0:
                print(f"Function {func.get_name()} at {func.get_entry_point()} is not called")
                self.current_program.function_manager.remove_function(func.get_entry_point())
                self.set_eol_comment(func.get_entry_point(), "Function Removed by ClearOrphanFunctions.py")

if __name__ == "__main__":
    script = ClearOrphanFunctions()
    try:
        script.run()
    except Exception as e:
        print(f"An error occurred: {e}")
