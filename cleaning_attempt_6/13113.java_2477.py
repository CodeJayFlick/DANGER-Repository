class ARM_MachoRelocationHandler:
    def can_relocate(self, header):
        return header.get_cpu_type() == "CPU_TYPE_ARM"

    def is_paired_relocation(self, relocation):
        return (relocation.type == 0x1 or 
                relocation.type == 0x2 or 
                relocation.type == 0x4 or 
                relocation.type == 0x8)

    def relocate(self, relocation):
        if not relocation.requires_relocation():
            return

        relocation_info = relocation.get_relocation_info()
        target_addr = relocation.get_target_address()
        orig = self.read(relocation)
        
        if relocation_info.type in [0x1, 0x2]:
            # Vanilla
            if not relocation_info.is_pc_relocated:
                self.write(relocation, target_addr.offset)
            else:
                raise NotFoundException("Unimplemented relocation")
            
        elif relocation_info.type == 0x4: 
            # BL and BLX
            blx = (orig & 0xd000f800) == 0xc000f000
            s = (orig >> 10) & 0x1
            j1 = (orig >> 29) & 0x1
            j2 = (orig >> 27) & 0x1
            i1 = ~(j1 ^ s) & 0x1
            i2 = ~(j2 ^ s) & 0x1
            imm10 = orig & 0x3ff
            imm11 = (orig >> 16) & 0x7ff
            addend = ((s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1))
            if s:
                addend |= 0xfe000000
            else:
                addend &= ~0x3
            
            value = target_addr.offset + addend
            s = (value >> 24) & 0x1
            i1 = (value >> 23) & 0x1
            i2 = (value >> 22) & 0x1
            j1 = ~(i1 ^ s) & 0x1
            j2 = ~(i2 ^ s) & 0x1
            imm10 = (value >> 12) & 0x3ff
            imm11 = (value >> 1) & 0x7ff
            
            instr = orig & ((blx and 0xc000f800 or 0xd000f800))
            instr |= ((j1 << 29) | (j2 << 27) | (imm11 << 16) | (s << 10) | imm10)
            
            self.write(relocation, instr)

        else:
            raise NotFoundException("Unimplemented relocation")

    def read(self, relocation):
        # implement this method
        pass

    def write(self, relocation, value):
        # implement this method
        pass


class MachoRelocationHandler:
    def __init__(self):
        self.arm_macho_relocation_handler = ARM_MachoRelocationHandler()

    def can_relocate(self, header):
        return self.arm_macho_relocation_handler.can_relocate(header)

    def is_paired_relocation(self, relocation):
        return self.arm_macho_relocation_handler.is_paired_relocation(relation)


class NotFoundException(Exception):
    pass
