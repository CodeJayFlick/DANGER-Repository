class DWARFExpression:
    EMPTY_OPERANDS_VALUE = []

    def __init__(self, operations):
        self.operations = operations
        self.last_active_op_index = find_last_active_op_index()

    @staticmethod
    def expr_to_string(expr_bytes, diea):
        try:
            expr = DWARFEvaluator().create(diea.get_head_fragment()).read_expr(expr_bytes)
            return str(expr)
        except Exception as e:
            return "Unable to parse DWARF expression. Raw bytes: " + NumericUtilities.convert_bytes_to_string(expr_bytes)

    @staticmethod
    def read(expr_bytes, addr_size, is_little_endian, dwarf_format):
        provider = ByteArrayProvider(expr_bytes)
        reader = BinaryReader(provider, is_little_endian)

        return read(reader, addr_size, dwarf_format)

    @staticmethod
    def read(reader, addr_size, dwarf_format):
        operations = []

        try:
            opcode_offset = None
            invalid_opcode_encountered = False

            while (opcode_offset := reader.get_pointer_index()) < reader.length():
                opcode = reader.read_next_unsigned_byte()
                if not DWARFExpressionOpCodes.is_valid_opcode(opcode):
                    # consume the remainder of the bytes in the expression because we've hit an invalid opcode and can't proceed any further.
                    bytes_left = (reader.length() - reader.get_pointer_index())
                    operations.append(DWARFExpressionOperation(opcode, DWARFExpressionOpCodes.BLOBONLY_OPERANDTYPES,
                                                              EMPTY_OPERANDS_VALUE,
                                                              read_sized_blob_operand(reader, bytes_left),
                                                              int(opcode_offset)))
                    invalid_opcode_encountered = True
                else:
                    operand_types = DWARFExpressionOpCodes.get_operand_types_for(opcode)

                    operands_values = [None] * len(operand_types)
                    blob = None
                    for i in range(len(operand_types)):
                        optype = operand_types[i]
                        if optype == DWARFExpressionOperandType.SIZED_BLOB:
                            blob = read_sized_blob_operand(reader, operands_values[i - 1])
                        else:
                            operands_values[i] = read_operand_value(optype, reader, addr_size, dwarf_format)

                    op = DWARFExpressionOperation(opcode, operand_types, operands_values, blob, int(opcode_offset))
                    operations.append(op)
        except Exception as e:
            if invalid_opcode_encountered:
                raise IOException("Unknown DWARF opcode(s) encountered")
            else:
                bad_expr = self(operations)
                s = str(bad_expr)
                raise DWARFEvaluationException(
                    "Error reading DWARF expression, partial expression is: ", bad_expr, -1, e)

        return self(operations)

    @staticmethod
    def read_operand_value(optype, reader, addr_size, dwarf_format):
        try:
            match optype:
                case DWARFExpressionOperandType.ADDR:
                    return DWARFUtil.read_address_as_long(reader, addr_size)
                case DWARFExpressionOperandType.S_BYTE | DWARFExpressionOperandType.U_BYTE:
                    return reader.read_next_byte()
                case DWARFExpressionOperandType.S_SHORT | DWARFExpressionOperandType.U_SHORT:
                    return reader.read_next_short()
                case DWARFExpressionOperandType.S_INT | DWARFExpressionOperandType.U_INT:
                    return reader.read_next_int()
                case DWARFExpressionOperandType.S_LONG | DWARFExpressionOperandType.U_LONG:
                    return reader.read_next_long()  # & there is no mask for ulong
                case DWARFExpressionOperandType.LEB128:
                    return LEB128.read_as_long(reader, True)
                case DWARFExpressionOperandType.UBLEB128:
                    return LEB128.read_as_long(reader, False)
        except ArrayIndexOutOfBoundsException as aioob:
            raise IOException("Not enough bytes to read " + optype)

    @staticmethod
    def read_sized_blob_operand(reader, previous_operand_value):
        return reader.read_next_byte_array(int(previous_operand_value))

    def get_op(self, i):
        return self.operations[i]

    def get_op_count(self):
        return len(self.operations)

    def get_last_active_op_index(self):
        return self.last_active_op_index

    @staticmethod
    def find_last_active_op_index():
        for i in range(len(DWARFExpressionOperations) - 1, -1, -1):
            if DWARFExpressionOperations[i].get_opcode() != DWARFExpressionOpCodes.DW_OP_NOP:
                return i
        return len(DWARFExpressionOperations) - 1

    def find_op_by_offset(self, offset):
        for i in range(len(self.operations)):
            op = self.get_op(i)
            if op.get_offset() == offset:
                return i
        return -1

    @staticmethod
    def to_string(caret_position=-1, newlines=False, offsets=False):
        sb = StringBuilder()
        for step in range(len(DWARFExpressionOperations)):
            op = DWARFExpressionOperations[step]

            if step != 0:
                sb.append("; ")
                if newlines:
                    sb.append('\n')
            if offsets:
                sb.append(f"{step:03d} [{op.get_offset():x}]: ")

            if caret_position == step:
                sb.append("==> [")
            opcode = op.get_opcode()
            if DWARFExpressionOpCodes.is_valid_opcode(opcode):
                sb.append(DWARFExpressionOpCodes.to_string(opcode))
            else:
                if opcode >= DWARFExpressionOpCodes.DW_OP_lo_user and opcode <= DWARFExpressionOpCodes.DW_OP_hi_user:
                    rel_op_code = opcode - DWARFExpressionOpCodes.DW_OP_lo_user
                    sb.append(f"{DWARFExpressionOpCodes.to_string(DWARFExpressionOpCodes.DW_OP_lo_user)}+{rel_op_code} [{opcode}]")
                else:
                    sb.append("DW_OP_UNKNOWN[" + str(opcode) + "]")

            for operand_index in range(len(op.operands)):
                if operand_index == 0:
                    sb.append(':')
                sb.append(' ')
                optype = op.operand_types[operand_index]
                if optype != DWARFExpressionOperandType.SIZED_BLOB:
                    value = op.operands[operand_index]

                    sb.append(DWARFExpressionOperandType.value_to_string(value, optype))
                else:
                    sb.append(NumericUtilities.convert_bytes_to_string(op.blob, " "))

            if caret_position == step:
                sb.append("] <==")
            if opcode in [DWARFExpressionOpCodes.DW_OP_bra, DWARFExpressionOpCodes.DW_OP_skip]:
                dest_offset = op.get_operand_value(0) + op.get_offset()
                dest_index = self.find_op_by_offset(dest_offset)
                sb.append(f" /* dest index: {dest_index}, offset: {int(dest_offset):x} */")

        return str(sb)

class DWARFEvaluator:
    def create(self, diea):
        pass

    def read_expr(self, expr_bytes):
        pass
