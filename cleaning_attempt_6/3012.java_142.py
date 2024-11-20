import ghidra_app_script as GAS
from ghidra_program_model import Address, CodeUnit
from ghidra_util import IntPropertyMap, PropertyMapManager

class DeleteSpacePropertyScript:
    def run(self):
        prop_mgr = currentProgram.getUsrPropertyManager()
        map = prop_mgr.getIntPropertyMap(CodeUnit.SPACE_PROPERTY)
        
        if map is not None:
            iter = map.getPropertyIterator()
            list = []
            
            while iter.hasNext():
                list.append(iter.next())
                
            str = "s" if len(list) > 1 else ""
            print(f"Removed space property from {len(list)} address{str}.")
            
            for i in range(len(list)):
                addr = list[i]
                map.remove(addr)
        else:
            print("No space properties were found.")

# Usage
script = DeleteSpacePropertyScript()
try:
    script.run()
except Exception as e:
    print(f"An error occurred: {e}")
