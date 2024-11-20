import ghidra.app.script.GhidraScript
from ghidra.program.model.lang import OperandType
from ghidra.program.model.listing import InstructionIterator
from ghidra.program.model.mem import MemoryAccessException
from ghidra. program.model.scalar import Scalar

class SetEquateScript(GhidraScript):
    def run(self) -> None:
        # Get listing for current program
        listing = self.currentProgram.getListing()

        scalar_found = False
        user_scalar_found = False

        # Prompt user to input scalar value to search for
        scalar_value = int(input("Please input the scalar value you want to search for: "))

        # Prompt user to input the name for the equate
        equate_name = str(input("Please input the name of the equate you wish to add: "))
        
        if self.currentSelection is not None:
            iter = listing.getInstructions(self.currentSelection, True)
        else:
            try:
                iter = listing.getInstructions(self.currentProgram.getMemory(), True)
            except MemoryAccessException as e:
                print(f"Error accessing memory: {e}")
                return

        while iter.hasNext():
            temp_value = iter.next()
            
            num_operands = temp_value.getNumOperands()

            for i in range(num_operands):
                if temp_value.getOperandType(i) == OperandType.SCALAR:
                    scalar_found = True
                    
                    if temp_value.getScalar(i).getUnsignedValue() == scalar_value:
                        user_scalar_found = True
                        
                        try:
                            cmd = SetEquateCmd(equate_name, temp_value.getAddress(), i, scalar_value)
                            self.state.getTool().execute(cmd, self.currentProgram)

                            print(f"A new equate named {equate_name} has been set for the scalar value {scalar_value} at address {temp_value.getAddress()} and at operand {i}")
                        except Exception as e:
                            print(f"Error setting equate: {e}")

        if not scalar_found or not user_scalar_found:
            print("No scalar values were found.")
        elif not user_scalar_found:
            print(f"No {scalar_value} values were found")
