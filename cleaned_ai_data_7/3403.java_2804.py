class CliMetadataTokenAnalyzer:
    NAME = "CLI Metadata Token Analyzer"
    DESCRIPTION = "Takes CLI metadata tokens from their table/index form and gives a more useful representation."

    def __init__(self):
        self.set_supports_one_time_analysis()
        self.set_priority(AnalysisPriority.CODE_ANALYSIS)
        self.set_prototype()

    def get_default_enablement(self, program):
        return program.get_language().get_id() == "CLI"

    def can_analyze(self, program):
        return self.get_default_enablement(program)

    def added(self, program, set, monitor, log):
        metadata_root_symbol = SymbolUtilities.get_expected_label_or_function_symbol(program,
            CliMetadataRoot.NAME, err=lambda x: log.append_msg(self.name(), x))
        
        if metadata_root_symbol is None:
            message = "CLI Metadata Root Symbol not found."
            log.append_msg(self.name(), message)
            log.set_status(message)
            return False
        
        metadata_root_addr = metadata_root_symbol.get_address()
        bytes = MemoryByteProvider(program.memory, metadata_root_addr)
        reader = BinaryReader(bytes, program.language.is_big_endian())
        
        try:
            metadata_root = CliMetadataRoot(reader, 0)
            metadata_root.parse()
            
            metadata_stream = metadata_root.get_metadata_stream()
            
            return self.process_managed_instructions(program, set, monitor, log, metadata_root)
        except IOException as e:
            message = str(e)
            log.append_msg(self.name(), message)
            log.set_status(message)
            return False

    def process_managed_instructions(self, program, set, monitor, log, metadata_root):
        inst_iter = program.listing().get_instructions(set, True)

        while inst_iter.has_next():
            try:
                instruction = inst_iter.next()
                
                if instruction.get_mnemonic_string().endswith("ldstr"):
                    self.process_user_string(metadata_stream, instruction)
                    
                elif instruction.get_mnemonic_string().endswith("call") or \
                     instruction.get_mnemonic_string().endswith("calli") or \
                     instruction.get_mnemonic_string().endswith("jmp"):
                    self.process_control_flow_instruction(program, metadata_stream, instruction,
                        RefType.UNCONDITIONAL_CALL if instruction.get_mnemonic_string().endswith("call")
                            else (RefType.COMPUTED_CALL if instruction.get_mnemonic_string().endswith("calli") 
                                  else RefType.UNCONDITIONAL_JUMP))
                    
                elif instruction.get_mnemonic_string().endswith("ldftn"):
                    self.process_generic_metadata_token(metadata_stream, instruction)
                
                # Object Model Instructions
                elif instruction.get_mnemonic_string().startswith(("box", "castclass", "cpobj",
                                                                  "initobj", "isinst", "ldelem", 
                                                                  "ldelema", "ldfld", "ldflda", 
                                                                  "ldobj", "ldsfld", "ldsflda", "ldtoken", 
                                                                  "mkrefany", "newarr", "newobj", 
                                                                  "refanyval", "sizeof", "stelem", 
                                                                  "stfld", "stobj", "stsfld", "unbox")):
                    self.process_object_model_instruction(program, metadata_stream, instruction)
                    
                elif instruction.get_mnemonic_string().endswith("callvirt"):
                    self.process_control_flow_instruction(program, metadata_stream, instruction,
                        RefType.COMPUTED_CALL)  # TODO: Computed call because this is a virtual function on an object
                elif instruction.get_mnemonic_string().endswith("constrained"):
                    table_row = get_row_for_metadata_token(metadata_stream, instruction)
                    self.mark_metadata_row(instruction, table_row, "Next instr type req'ed to be:", "",
                                            metadata_stream)
                    
                elif instruction.get_mnemonic_string().endswith("ldvirtfn"):
                    self.process_object_model_instruction(program, metadata_stream, instruction)  # TODO: ldvirtfn puts virtual method pointer on stack
            except Exception as e:
                e.print_stack_trace()  # TODO:

        return True

    def process_user_string(self, meta_stream, inst):
        str_index_op = (Scalar)(inst.get_op_objects(0)[0])
        
        str_index = int(str_index_op.get_unsigned_value())
        
        inst.set_comment(CodeUnit.EOL_COMMENT,
            f"\"{meta_stream.user_strings_stream().get_user_string(str_index)}\"")

    def process_control_flow_instruction(self, program, meta_stream, inst, ref_type):
        table_row = get_row_for_metadata_token(meta_stream, inst)
        self.mark_metadata_row(inst, table_row, meta_stream)

        if isinstance(table_row, CliMethodDefRow):
            method_def = (CliMethodDefRow)(table_row)
            
            if method_def.rva != 0:
                dest_addr = program.address_factory().get_default_address_space().get_address(method_def.rva)  # TODO: RVA isn't the right address to use in raw binary format. Don’t know in PE.
                
                inst.add_operand_reference(1, dest_addr, ref_type, SourceType.ANALYSIS)

    def get_row_for_metadata_token(self, meta_stream, inst):
        ops = inst.get_op_objects(0)
        
        table_op = (Scalar)(ops[0])
        index_op = (Scalar)(ops[1])
        
        table = int(table_op.get_unsigned_value())
        index = int(index_op.get_unsigned_value())
        
        return meta_stream.table(table).get_row(index)

    def mark_metadata_row(self, inst, table_row, prepend_comment="", append_comment="", stream=None):
        inst.set_comment(CodeUnit.EOL_COMMENT,
            f"{prepend_comment}{table_row.short_representation(stream)}{append_comment}")

    def process_generic_metadata_token(self, meta_stream, inst):
        table_row = get_row_for_metadata_token(meta_stream, inst)
        
        self.mark_metadata_row(inst, table_row, meta_stream)

    def process_object_model_instruction(self, program, meta_stream, inst):
        table_row = get_row_for_metadata_token(meta_stream, inst)
        
        self.mark_metadata_row(inst, table_row, "", " (Object Model Instruction)", meta_stream)


# Usage
if __name__ == "__main__":
    analyzer = CliMetadataTokenAnalyzer()
