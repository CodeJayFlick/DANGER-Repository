Here is the translation of the Java code into Python:

```Python
class ByteSequenceRowObject:
    def __init__(self, byte_sequence: str, disassembly: str, num_occurrences: int, percentage: float):
        self.byte_sequence = byte_sequence
        self.disassembly = disassembly
        self.num_occurrences = num_occurrences
        self.percentage = percentage

def get_filtered_row_objects(unfiltered_info: list, pattern_type: PatternType, register_filter: ContextRegisterFilter, length_filter: ByteSequenceLengthFilter) -> List[ByteSequenceRowObject]:
    byte_seq_counts = {}
    bytes_to_disassembly = {}
    total_num_seqs = 0
    for f_info in unfiltered_info:
        if fails_filter(f_info, register_filter):
            continue

        filtered_bytes_and_disassembly = get_filtered_bytes_and_disassembly(get_all_byte_strings_of_type(f_info, pattern_type), length_filter, f_info, pattern_type)
        
        num_filtered_strings = len(filtered_bytes_and_disassembly.filtered_bytes)

        for i in range(num_filtered_strings):
            current_filtered_byte_string = filtered_bytes_and_disassembly.filtered_bytes[i]
            if bytes_to_disassembly.get(current_filtered_byte_string) is None or len(bytes_to_disassembly[current_filtered_byte_string]) < len(disassembly[i]):
                bytes_to_disassembly[bytes_to_disassembly] = disassembly[i]

        for i in range(num_filtered_strings):
            current_filtered_byte_string = filtered_bytes_and_disassembly.filtered_bytes[i]
            if byte_seq_counts.get(current_filtered_byte_string) is None:
                byte_seq_counts[current_filtered_byte_string] = 1
                total_num_seqs += 1
            else:
                byte_seq_counts[byte_seq_counts] += 1

    return get_row_objects_for_length_filtered_seqs(byte_seq_counts, bytes_to_disassembly, total_num_seqs)

def get_row_objects_for_length_filtered_seqs(byte_seq_counts: dict, bytes_to_disassembly: dict, total_num_seqs: int) -> List[ByteSequenceRowObject]:
    row_objects = []
    
    for byte_sequence in byte_seq_counts:
        count = byte_seq_counts[byte_sequence]
        row_object = ByteSequenceRowObject(byte_sequence, bytes_to_disassembly[byte_sequence], count, 100.0 * count / total_num_seqs)
        row_objects.append(row_object)

    return row_objects

def get_filtered_bytes_and_disassembly(byte_strings: list, length_filter: ByteSequenceLengthFilter, f_info: FunctionBitPatternInfo, pattern_type: PatternType) -> FilteredBytesAndDisassembly:
    filtered_byte_strings = []
    disassemblies = []

    for i in range(len(byte_strings)):
        current_byte_string = byte_strings[i]
        
        if length_filter is not None and len(current_byte_string) < HEX_DIGITS_PER_BYTE * 2:
            continue

        if pattern_type == PatternType.FIRST:
            filtered_byte_strings.append(f_info.get_first_bytes())
            disassemblies.append(get_complete_disassembly(f_info, pattern_type, i))
        elif pattern_type == PatternType.PRE:
            filtered_byte_strings.append(f_info.get_pre_bytes())
            disassemblies.append(get_complete_disassembly(f_info, pattern_type, 0))
        elif pattern_type == PatternType.RETURN:
            if f_info.get_return_bytes() is None or len(f_info.get_return_bytes()) <= i:
                continue
            filtered_byte_strings.extend(f_info.get_return_bytes()[i:])
            disassemblies.append(get_complete_disassembly(f_info, pattern_type, 0))

    return FilteredBytesAndDisassembly(filtered_byte_strings, disassemblies)

def get_all_byte_strings_of_type(f_info: FunctionBitPatternInfo, pattern_type: PatternType) -> list:
    if pattern_type == PatternType.FIRST:
        return [f_info.get_first_bytes()]
    elif pattern_type == PatternType.PRE:
        return [f_info.get_pre_bytes()]
    elif pattern_type == PatternType.RETURN:
        return f_info.get_return_bytes()

def get_complete_disassembly(f_info: FunctionBitPatternInfo, pattern_type: PatternType, i: int) -> str:
    if pattern_type == PatternType.FIRST:
        return f_info.get_first_inst().get_complete_disassembly(True)
    elif pattern_type == PatternType.PRE:
        return f_info.get_pre_inst().get_complete_disassembly(False)
    elif pattern_type == PatternType.RETURN:
        return f_info.get_return_inst()[i].get_complete_dissembly(False)

def get_row_objects_from_instruction_sequences(unfiltered_info: list, path_filter: InstructionSequenceTreePathFilter) -> List[ByteSequenceRowObject]:
    total_num_seqs = 0
    bytes_and_dis_count = {}

    for f_info in unfiltered_info:
        if fails_filter(f_info, context_register_filter):
            continue

        inst_seqs = get_instruction_sequences(path_filter, f_info)

        for i in range(len(inst_seqs)):
            current_seq = inst_seqs[i]
            
            total_bytes = None
            bytes = None
            disassembly = None
            
            if path_filter.get_instruction_type() == PatternType.FIRST:
                total_bytes = f_info.get_first_bytes()
                bytes = total_bytes[:HEX_DIGITS_PER_BYTE * len(current_seq)]
                disassembly = get_dissembly_for_tree_path(current_seq, path_filter)
            elif path_filter.get_instruction_type() == PatternType.PRE:
                total_bytes = f_info.get_pre_bytes()
                bytes = total_bytes[-HEX_DIGITS_PER_BYTE * len(current_seq):]
                disassembly = get_dissembly_for_tree_path(current_seq, path_filter)
            elif path_filter.get_instruction_type() == PatternType.RETURN:
                if i >= len(f_info.get_return_inst()):
                    continue
                total_bytes = f_info.get_return_bytes()[i]
                bytes = total_bytes[-HEX_DIGITS_PER_BYTE * len(current_seq):]
                disassembly = get_dissembly_for_tree_path(current_seq, path_filter)

            increment_count_map(bytes_and_dis_count, bytes, disassembly)
            
    return get_row_objects_for_path_filtered_seqs(bytes_and_dis_count, total_num_seqs)

def get_instruction_sequences(path_filter: InstructionSequenceTreePathFilter, f_info: FunctionBitPatternInfo) -> list:
    inst_seq = []

    if path_filter.get_instruction_type() == PatternType.FIRST:
        if f_info.get_first_bytes():
            inst_seq.append(f_info.get_first_inst())
    elif path_filter.get_instruction_type() == PatternType.PRE:
        if f_info.get_pre_bytes():
            inst_seq.append(f_info.get_pre_inst())
    elif path_filter.get_instruction_type() == PatternType.RETURN:
        ret_bytes = f_info.get_return_bytes()
        
        for i in range(len(ret_bytes)):
            if len(f_info.get_return_inst()) <= i:
                break
            inst_seq.extend(f_info.get_return_inst())

def merge(row_objects: list) -> DittedBitSequence:
    ditted_seqs = []

    for row_object in row_objects:
        current_seq = DittedBitSequence(row_object.byte_sequence, True)
        ditted_seqs.append(current_seq)

    if len(ditted_seqs) > 1:
        return ditted_seqs[0]
    else:
        return None

class PatternType(Enum):
    FIRST
    PRE
    RETURN

class ContextRegisterFilter:
    def allows(self, context_registers: list) -> bool:
        pass

class ByteSequenceLengthFilter:
    def filter(self, byte_string: str) -> str:
        pass

class FilteredBytesAndDisassembly:
    def __init__(self, filtered_bytes: list, disassemblies: list):
        self.filtered_bytes = filtered_bytes
        self.disassemblies = disassemblies

def get_dissembly_for_tree_path(inst_seq: InstructionSequence, path_filter: InstructionSequenceTreePathFilter) -> str:
    pass

class DittedBitSequence:
    def __init__(self, byte_sequence: str, is_ditted: bool):
        self.byte_sequence = byte_sequence
        self.is_ditted = is_ditted