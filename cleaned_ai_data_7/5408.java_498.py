class MachoPrelinkProgramBuilder:
    def __init__(self, program, provider, file_bytes, prelink_list, log):
        self.prelink_list = prelink_list

    @staticmethod
    def build_program(program, provider, file_bytes, prelink_list, log):
        macho_prelink_program_builder = MachoPrelinkProgramBuilder(
            program, provider, file_bytes, prelink_list, log)
        try:
            macho_prelink_program_builder.build()
        except Exception as e:
            print(f"An error occurred: {e}")

    def build(self):
        super().build()

        fixed_addresses = self.fixup_chained_pointers()

        if not MachoPrelinkUtils.find_prelink_macho_header_offsets(
                self.provider, self.monitor).isEmpty():
            macho_header_offsets = MachoPrelinkUtils.\
                find_prelink_macho_header_offsets(self.provider, self.monitor)
            prelink_map = MachoPrelinkUtils.match_prelink_to_macho_header_offsets(
                self.provider, self.prelink_list, macho_header_offsets, self.monitor)

            if not fixed_addresses:
                return

            prelink_start_addr = None
            if 0 == prelink_start_addr:
                # Probably iOS 12, which doesn't define a proper __PRELINK_TEXT segment.
                # Assume the file offset is the same as the offset from image base.
                prelink_start_addr = self.program.get_image_base().add(
                    macho_header_offsets[0])
            else:
                prelink_start_addr = space.get_address(prelink_start)

            for i, info in enumerate(MachoPrelinkUtils.\
                    find_prelink_macho_info(self.provider, self.prelink_list)):
                if not fixed_addresses[i]:
                    continue
                try:
                    info.process_memory_blocks()
                    info.markup_headers()
                    info.add_to_program_tree(None)
                except Exception as e:
                    print(f"An error occurred: {e}")

            for i in range(len(prelink_macho_info_list) - 1):
                prelink_macho_info = prelink_macho_info_list[i]
                next_prelink_macho_info = prelink_macho_info_list[i + 1]

    def fixup_chained_pointers(self):
        thread_starts_section = self.macho_header.get_section(
            SegmentNames.SEG_TEXT, "__thread_starts")
        if not thread_starts_section:
            return []

        monitor.set_message("Fixing up chained pointers...")

        fixed_addresses = []
        address_thread_section_start = space.get_address(thread_starts_section.address)
        address_thread_section_end = address_thread_section_start.add(
            thread_starts_section.size - 1)

        next_off_size = memory.get_int(address_thread_section_start) & 0x1 * 4 + 4
        address_chain_head = address_thread_section_start.add(4)

        while (address_chain_head < address_thread_section_end and not monitor.is_cancelled()):
            head_start_offset = memory.get_int(address_chain_head)
            if head_start_offset == 0xFFFFFFFF or head_start_offset == 0:
                break

            address_chain_start = self.program.get_image_base().add(
                head_start_offset & 0xffffffffL)

            fixed_addresses.extend(self.process_pointer_chain(
                address_chain_start, next_off_size))

            address_chain_head = address_chain_head.add(4)

        log.append_msg(f"Fixed up {len(fixed_addresses)} chained pointers.")
        return fixed_addresses

    def process_pointer_chain(self, chain_start, next_off_size):
        fixed_addresses = []

        while not monitor.is_cancelled():
            chain_value = memory.get_long(chain_start)
            self.fixup_pointer(chain_start, chain_value)

            fixed_addresses.append(chain_start)

            if (chain_value >> 51) & 0x7ff:
                break

            next_value_off = ((chain_value >> 51) & 0x7ff) * next_off_size
            if not next_value_off:
                break

            address_chain_head = chain_start.add(next_value_off)
        return fixed_addresses

    def fixup_pointer(self, pointer_addr, pointer_value):
        BIT63 = (1 << 63)
        BIT62 = (1 << 62)

        # Bad chain value
        if ((pointer_value & BIT62) != 0):
            pass

        fixed_pointer_value = 0
        fixed_pointer_type = 0

        # Pointer checked value
        if ((pointer_value & BIT63) != 0):
            pac_mod = (pointer_value >> 32) & 0xffff
            fixed_pointer_type = pac_mod
            fixed_pointer_value = self.program.get_image_base().get_offset() + (
                pointer_value & 0xffffffffL)
        else:
            fixed_pointer_value = ((pointer_value << 13) & 0xff00000000000000L) | (
                pointer_value & 0x7ffffffffffL)

            if (pointer_value & 0x40000000000):
                fixed_pointer_value |= 0xfffc0000000000L

        # Add entry to relocation table for the pointer fixup
        orig_bytes = memory.get_bytes(pointer_addr, 8)
        self.program.get_relocation_table().add(
            pointer_addr,
            int(fixed_pointer_type),
            [fixed_pointer_value],
            orig_bytes,
            None)

        # Fixup the pointer
        memory.set_long(pointer_addr, fixed_pointer_value)

    class PrelinkMachoInfo:
        def __init__(self, provider, offset, header_addr, prelink):
            self.header_addr = header_addr

        def process_memory_blocks(self):
            try:
                MachoPrelinkProgramBuilder.build_program(
                    None,
                    self.provider,
                    None,
                    [self],
                    None)
            except Exception as e:
                print(f"An error occurred: {e}")

        def markup_headers(self):
            if not self.name.empty():
                listing.set_comment(self.header_addr, CodeUnit.PLATE_COMMENT, self.name)

        def add_to_program_tree(self, next):
            if not self.name.empty():
                fragment = listing.get_default_root_module().create_fragment(
                    self.name)
                if next:
                    fragment.move(self.header_addr, next.header_addr.subtract(1))
                else:
                    for section in macho_header.get_all_sections():
                        address_section_start = space.get_address(section.address)
                        if (self.header_addr >= address_section_start and
                                self.header_addr <= address_section_start.add(
                                    section.size - 1)):
                            fragment.move(self.header_addr, address_section_start.add(
                                section.size - 1))
