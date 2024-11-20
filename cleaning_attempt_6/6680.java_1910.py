class InstructionSequence:
    def __init__(self):
        self.instructions = []
        self.sizes = []
        self.comma_separated_operands = []

    @staticmethod
    def get_complete_disassembly(instructions, sizes, comma_separated_operands, in_order=True):
        if not instructions or len(instructions) == 0:
            return None

        sb = StringBuilder()
        for i in range(len(instructions)):
            current_inst = i
            sb.append("  ")
            sb.append(instructions[current_inst])
            sb.append(":")
            sb.append(str(sizes[current_inst]))
            if comma_separated_operands and comma_separated_operands[i]:
                sb.append("(")
                sb.append(comma_separated_operands[i])
                sb.append(")")
            else:
                sb.append("()")
            if in_order:
                sb.insert(0, "  ")
            else:
                sb.append("\n")
        return str(sb)

    def get_disassembly(self, num_instructions, in_order=True):
        if not self.instructions or len(self.instructions) == 0:
            return None

        if num_instructions > len(self.instructions):
            raise ValueError("Too many instructions requested!")

        current_inst = 0
        while current_inst < num_instructions:
            sb = StringBuilder()
            sb.append("  ")
            sb.append(self.instructions[current_inst])
            sb.append(":")
            sb.append(str(self.sizes[current_inst]))
            if self.comma_separated_operands and self.comma_separated_opernds[current_inst]:
                sb.append("(")
                sb.append(self.comma_separated_operands[current_inst])
                sb.append(")")
            else:
                sb.append("()")
            if in_order:
                sb.insert(0, "  ")
            else:
                sb.insert(0, "\n")
            current_inst += 1
        return str(sb)

    def get_instructions(self):
        return self.instructions

    def set_instructions(self, instructions):
        self.instructions = instructions

    def get_sizes(self):
        return self.sizes

    def set_sizes(self, sizes):
        self.sizes = sizes

    def get_comma_separated_operands(self):
        return self.comma_separated_operands

    def set_comma_separated_operands(self, comma_separated_operands):
        self.comma_separated_operands = comma_separated_operands

    def __hash__(self):
        hashcode = 17
        for i in range(len(self.instructions)):
            if not isinstance(self.sizes[i], int) or not isinstance(self.comma_separated_operands[i], str):
                return None
            hashcode *= 31 + self.instructions[i].__hash__()
            hashcode *= 31 + self.sizes[i]
            if self.comma_separated_operands and i < len(self.comma_separated_operands) - 1:
                hashcode *= 31 + self.comma_separated_operands[i].__hash__()
        return hashcode

    def __eq__(self, other):
        if not isinstance(other, InstructionSequence):
            return False
        for i in range(len(self.instructions)):
            if self.instructions[i] != other.get_instructions()[i]:
                return False
            if self.sizes[i] != other.get_sizes()[i]:
                return False
            if self.comma_separated_operands and i < len(self.comma_separated_operands) - 1:
                if self.comma_separated_operands[i].lower() != other.get_comma_separated_operands()[i].lower():
                    return False
        return True

    def __str__(self):
        sb = StringBuilder()
        for instruction in self.instructions:
            sb.append(instruction)
            sb.append(":")
            sb.append(str(self.sizes[self.instructions.index(instruction)]))
            if self.comma_separated_operands and self.comma_separated_operands[self.instructions.index(instruction)].lower():
                sb.append("(")
                sb.append(self.comma_separated_operands[self.instructions.index(instruction)])
                sb.append(")")
        return str(sb)

    @staticmethod
    def get_inst_seqs(fs_reader, type, reg_filter):
        inst_seq_list = []
        for f_info in fs_reader.get_finfo_list():
            if reg_filter and not reg_filter.allows(f_info.get_context_registers()):
                continue

            switch (type):
                case "FIRST":
                    current_seq = f_info.get_first_inst()
                    if current_seq.instructions[0] is not None:
                        inst_seq_list.append(current_seq)
                    break
                case "PRE":
                    current_seq = f_info.get_pre_inst()
                    if current_seq.instructions[0] is not None:
                        inst_seq_list.append(current_seq)
                    break
                case "RETURN":
                    for i in range(len(f_info.get_return_inst())):
                        if f_info.get_return_inst()[i].instructions[0] is not None and f_info.get_return_bytes()[i]:
                            inst_seq_list.append(f_info.get_return_inst()[i])
                    break

        return inst_seq_list

    @staticmethod
    def to_xml(self, element_name="InstructionSequence"):
        result = Element(element_name)

        instructions_list_ele = Element("instructions")
        for instruction in self.instructions:
            x = Element("instruction")
            if instruction is not None:
                x.set_attribute("value", str(instruction))
            instructions_list_ele.add_content(x)
        result.add_content(instructions_list_ele)

        sizes_list_ele = Element("sizes")
        for size in self.sizes:
            x = Element("size")
            if size is not None:
                XmlUtilities.set_int_attr(x, "value", int(size))
            sizes_list_ele.add_content(x)
        result.add_content(sizes_list_ele)

        cso_list_ele = Element("commaSeparatedOperands")
        for operands in self.comma_separated_operands:
            x = Element("operands")
            if operands is not None:
                x.set_attribute("value", str(operands))
            cso_list_ele.add_content(x)
        result.add_content(cso_list_ele)

        return result

    @staticmethod
    def from_xml(element):
        if element is None:
            return None

        instructions = []
        sizes = []
        comma_separated_operands = []

        for child in XmlUtilities.get_children(element, "instruction"):
            val = child.get_attribute_value("value")
            if val is not None:
                instructions.append(val)

        for child in XmlUtilities.get_children(element, "size"):
            val = child.get_attribute_value("value")
            if val is not None:
                sizes.append(int(val))

        for child in XmlUtilities.get_children(element, "operands"):
            val = child.get_attribute_value("value")
            if val is not None:
                comma_separated_operands.append(val)

        return InstructionSequence(instructions, sizes, comma_separated_operands)
