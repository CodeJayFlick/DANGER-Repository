class X86_64_MachoRelocationHandler:
    def can_relocate(self, header):
        return header.get_cpu_type() == 'CPU_TYPE_X86_64'

    def is_paired_relocation(self, relocation):
        return relocation.get_type() == 'X86_64_RELOC_SUBTRACTOR'

    def relocate(self, relocation):
        if not relocation.requires_relocation():
            return

        relocation_info = relocation.get_relocation_info()
        reloc_addr = relocation.get_relocation_address()
        target_addr = relocation.get_target_address()
        addend = self.read(relocation)

        if relocation_info.get_type() in ['X86_64_RELOC_UNSIGNED', 'X86_64_RELOC_SIGNED',
                                          'X86_64_RELOC_BRANCH', 'X86_64_RELOC_GOT_LOAD',
                                          'X86_64_RELOC_GOT', 'X86_64_RELOC_SIGNED_1',
                                          'X86_64_RELOC_SIGNED_2', 'X86_64_RELOC_SIGNED_4']:
            self.write(relocation, target_addr.add(addend).subtract(reloc_addr) - 4)
        elif relocation_info.get_type() == 'X86_64_RELOC_SUBTRACTOR':
            target_addr_extra = relocation.get_target_address_extra()
            if addend > 0:
                self.write(relocation, target_addr_extra.add(addend).subtract(target_addr))
            else:
                self.write(relocation, target_addr.add(addend).subtract(target_addr_extra))
        elif relocation_info.get_type() == 'X86_64_RELOC_TLV':
            # not seen yet
            pass
        else:
            raise NotFoundException("Unimplemented relocation")

    def read(self, relocation):
        # implement this method to read the addend from the relocation
        pass

    def write(self, relocation, value):
        # implement this method to write the result of the relocation into memory
        pass


class MachoRelocationHandler:
    def requires_relocation(self):
        raise NotImplementedError("requires_relocation must be implemented")


class RelocationInfo:
    def get_type(self):
        raise NotImplementedError("get_type must be implemented")

    def get_target_address_extra(self):
        raise NotImplementedError("get_target_address_extra must be implemented")
