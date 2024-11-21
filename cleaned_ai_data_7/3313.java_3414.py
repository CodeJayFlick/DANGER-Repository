class CodeUnitDetails:
    NEW_LINE = "\n"
    INDENT1 = "     "

    def get_instruction_details(self, cu):
        if not cu or not isinstance(cu, Instruction):
            return "You must be on an instruction to see the details."
        return self.get_code_unit_details(cu) + self.get_reference_details(cu)

    def get_code_unit_details(self, cu):
        if not cu:
            return "You must be on a code unit to see the details."

        indent = self.INDENT1
        buf = ""
        buf += f"Code Unit:{self.NEW_LINE}"
        min_addr = cu.get_min_address()
        max_addr = cu.get_max_address()
        addr_range_str = f"{min_addr}{'-' + str(max_addr) if min_addr != max_addr else ''}"
        cu_rep = ""

        if isinstance(cu, Data):
            cu_rep += ((Data) cu).get_data_type().get_path_name() + self.NEW_LINE
        elif isinstance(cu, Instruction):
            inst = (Instruction) cu
            removed_fall_through = (
                inst.is_fall_through_overridden()
                and inst.get_fall_through() is None
            )
            has_flow_override = inst.get_flow_override() != FlowOverride.NONE

            if removed_fall_through:
                buf += f"{self.NEW_LINE}{indent}     Removed FallThrough"
            elif inst.is_fall_through_overridden():
                refs_from = cu.get_references_from()
                for i in range(len(refs_from)):
                    if refs_from[i].get_reference_type().is_fallthrough():
                        buf += (
                            f"{self.NEW_ LINE}{indent}     "
                            + "FallThrough Override: "
                            + DiffUtility.user_to_address_string(cu.get_program(), refs_from[i])
                        )
            if has_flow_override:
                buf += (
                    f"{self.NEW_LINE}{indent}     Flow Override: {inst.get_flow_override()}"
                )

        else:
            cu_rep = str(cu)

        buf += f"{indent}{addr_range_str}     {cu_rep}{self.NEW_LINE}"

        return buf

    def get_reference_details(self, cu):
        if not cu:
            return "You must be on a code unit to see the details."

        buf = ""
        buf += f"References: {self.NEW LINE}"
        buf += self.get_program_ref_details(cu.get_program(), cu.get_references_from())

        return buf

    def get_ref_info(self, pgm, ref):
        type_str = f"Type: {ref.get_reference_type()}"
        from_str = f"  From: {ref.get_from_address()}"
        operand_str = (
            "Mnemonic"
            if ref.is_mnemonic_reference()
            else (f" Operand: {ref.get_operand_index()}")
        )
        to_str = f"  To: {DiffUtility.user_to_address_string(pgm, ref)}"
        source_str = f"{ref.get_source().to_string()}"

        return type_str + from_str + operand_str + to_str + source_str

    def get_program_ref_details(self, pgm, refs):
        if len(refs) == 0:
            return "None"
        buf = ""
        indent = self.INDENT1
        for i in range(len(refs)):
            if refs[i].is_external_reference():
                buf += f"{indent}External Reference {self.get_ref_info(pgm, refs[i])}{self.NEW_LINE}"
            elif refs[i].is_stack_reference():
                buf += f"{indent}Stack Reference {self.get_ref_info(pgm, refs[i])}{self.NEW_LINE}"
            else:
                buf += f"{indent}Reference {self.get_ref_info(pgm, refs[i])}{self.NEW_LINE}"

        return buf

    def get_spaces(self, num_spaces):
        if num_spaces <= 0:
            return ""
        buf = StringBuffer(num_spaces)
        for i in range(num_spaces):
            buf.append(" ")
        return str(buf)

class Instruction:
    pass
