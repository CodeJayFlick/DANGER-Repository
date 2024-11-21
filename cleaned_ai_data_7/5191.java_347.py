class RelocByIndexGroup:
    kPEFRelocSmByImport = 0
    kPEFRelocSmSetSectC = 1
    kPEFRelocSmSetSectD = 2
    kPEFRelocSmBySection = 3

    def __init__(self, reader):
        value = reader.read_next_short() & 0xffff
        self.opcode = (value & 0xe000) >> 13
        self.subopcode = (value & 0x1e00) >> 9
        self.index = value & 0x01ff

    def is_match(self):
        return self.opcode == 3

    @property
    def subopcode(self):
        return self._subopcode

    @property
    def index(self):
        return self._index

    def __str__(self):
        if self.subopcode in [RelocByIndexGroup.kPEFRelocSmByImport,
                               RelocByIndexGroup.kPEFRelocSmSetSectC,
                               RelocByIndexGroup.kPEFRelocSmSetSectD]:
            return f"Reloc{['ByImport', 'SetSectC', 'SetSectD'][self.subopcode - 0]}"
        elif self.subopcode == RelocByIndexGroup.kPEFRelocSmBySection:
            return "RelocSmBySection"
        else:
            return super().__str__()

    def apply(self, import_state_cache, relocation_state,
              container_header, program, message_log, task_monitor):
        imported_symbols = container_header.get_loader().get_imported_symbols()
        
        if self.subopcode == RelocByIndexGroup.kPEFRelocSmByImport:
            try:
                imported_symbol = imported_symbols[self.index]
                library = container_header.get_loader().find_library(self.index)
                symbol_name = SymbolUtilities.replace_invalid_chars(imported_symbol.name, True)
                symbol = import_state_cache.get_symbol(symbol_name, library)
                relocation_state.relocate_memory_at(relocation_state.get_relocation_address(),
                                                      int(symbol.address.offset), message_log)
                relocation_state.increment_relocation_address(4)
                relocation_state.set_import_index(self.index + 1)
            except Exception as e:
                print(f"Error: {e}")
        
        elif self.subopcode in [RelocByIndexGroup.kPEFRelocSmSetSectC,
                                 RelocByIndexGroup.kPEFRelocSmSetSectD]:
            try:
                section_header = container_header.get_sections()[self.index]
                memory_block = import_state_cache.get_memory_block_for_section(section_header)
                if self.subopcode == RelocByIndexGroup.kPEFRelocSmSetSectC:
                    relocation_state.set_section_c(memory_block.start.offset)
                else:
                    relocation_state.set_section_d(memory_block.start.offset)
            except Exception as e:
                print(f"Error: {e}")
        
        elif self.subopcode == RelocByIndexGroup.kPEFRelocSmBySection:
            try:
                section_header = container_header.get_sections()[self.index]
                memory_block = import_state_cache.get_memory_block_for_section(section_header)
                relocation_state.relocate_memory_at(relocation_state.get_relocation_address(),
                                                      int(memory_block.start.offset), message_log)
            except Exception as e:
                print(f"Error: {e}")
        
        else:
            try:
                message_log.append_msg("Unsupported RelocByIndexGroup subopcode: " + str(self.subopcode))
            except Exception as e:
                print(f"Error: {e}")

