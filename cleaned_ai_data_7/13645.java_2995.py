import ghidra_app_script_gadget as gadget

class Lab5Script(gadget.GhidraScript):
    def run(self):
        for instruction in self.getInstructions():
            if self.isCancelled():
                break
            
            if len(instruction.getOpObjects()) != 2:
                continue
                
            op_objects0 = instruction.getOpObjects(0)
            if not isinstance(op_objects0[0], gadget.Register):
                continue

            op_objects1 = instruction.getOpObjects(1)
            if not isinstance(op_objects1[0], gadget.Scalar):
                continue

            register = op_objects0[0]
            scalar = op_objects1[0]

            comment = f"[{register.getName()}] = [{scalar.toString(16, False, False, '', '')}]"
            self.setEOLComment(instruction.getMinAddress(), comment)

# Initialize the script
script = Lab5Script()
try:
    script.run()
except Exception as e:
    print(f"An error occurred: {e}")
