Here is the translation of the Java code into Python:

```Python
import ghidra_app_script as ghidra

class DebugSleighInstructionParse:
    def run(self):
        if not hasattr(globals(), 'currentProgram') or not hasattr(globals(), 'currentAddress'):
            return
        
        try:
            logger = SleighDebugLogger(currentProgram, currentAddress, 1)
            
            if not logger.parseFailed():
                logger.append("\n")
                
                mask = logger.getInstructionMask()
                value = logger.getMaskedBytes(mask)
                
                logger.append("Instr Mask:   ")
                logger.append(get_formatted_bytes(mask))
                logger.append("\nInstr Value:  ")
                logger.append(get_formatted_bytes(value))
                
                for i in range(logger.getNumOperands()):
                    mask = logger.getOperandValueMask(i)
                    logger.append("\nOp-" + str(i) + " Mask:    " + get_formatted_bytes(mask))
                    logger.append("Op-" + str(i) + " Value:   " + get_formatted_bytes(logger.getMaskedBytes(mask)))
                print(logger.toString())
            
        except Exception as e:
            print(str(e))

    def get_formatted_bytes(self, value):
        buf = ""
        for i in range(len(value)):
            byte_str = format(int.from_bytes([value[i]], 'big'), '08b')
            buf += byte_str
            if i < len(value) - 1:
                buf += "."
        return buf

# Initialize the script
script = DebugSleighInstructionParse()
ghidra.run_script(script)
```

Please note that this is a direct translation of your Java code into Python.