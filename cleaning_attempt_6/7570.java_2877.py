import ghidra_app_script as GAS
from ghidra_feature_fid_hash import FidHashQuad
from ghidra_program_model_listing import FunctionManager

class FIDHashCurrentFunction(GAS.GhidraScript):
    def run(self):
        if not self.currentProgram:
            print("No current program")
            return
        
        if not self.currentAddress:
            print("No current address (?)")
            return
        
        function_manager = self.currentProgram.get_function_manager()
        function = function_manager.get_function_containing(self.currentAddress)
        
        if not function:
            print("No current function")
            return
        
        service = FidService()
        hash_function = service.hash_function(function)
        
        if not hash_function:
            print("Function too small")
            return
        
        print(f"FID Hash for {function.name} at {function.entry_point}: {hash_function}")
