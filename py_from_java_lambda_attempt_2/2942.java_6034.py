Here is the translation of the given Java code into Python:

```Python
import ghidra.app.script.GhidraScript
from ghidra.program.model.address import Address
from ghidra.util import disassemble
from typing import List

class GNUDisassembleBlockScript(GhidraScript):
    def run(self) -> None:
        if self.currentProgram is None or self.currentAddress is None:
            return
        
        dis = disassemble.GNUExternalDisassembler()
        
        addr = self.currentAddress.getNewAddress(self.currentAddress.getOffset() & -32)
        
        results: List[disassemble.GnuDisassembledInstruction] = dis.getBlockDisassembly(self.currentProgram, addr, 5)
        
        if results is None:
            print("Block Disassembly Failed!")
            return
        
        max_byte_len = 0
        for result in results:
            max_byte_len = max(max_byte_len, result.getNumberOfBytesInInstruction())
        
        sb = StringBuilder()
        for result in results:
            sb.append(str(addr))
            sb.append(' ')
            
            bytes = bytearray(result.getNumberOfBytesInInstruction())
            self.currentProgram.getMemory().getBytes(addr, bytes)
            
            for b in bytes:
                if 0 <= b < 16:
                    sb.append('0')
                sb.append(hex(b & 0xff).lstrip('0').lstrip(''))
                sb.append(' ')
            
            cnt = len(bytes)
            while cnt < max_byte_len:
                sb.append('   ')
                cnt += 3
            
            sb.append(str(result.getInstruction()))
            sb.append('\n')
            addr = addr.add(len(bytes))
        
        if sb.length() != 0:
            print("Block Disassembly:\n" + str(sb))

if __name__ == "__main__":
    script = GNUDisassembleBlockScript()
    script.run()
```

Please note that Python does not have a direct equivalent to Java's StringBuilder class. Instead, you can use the `str.join()` method or concatenate strings using the '+' operator.