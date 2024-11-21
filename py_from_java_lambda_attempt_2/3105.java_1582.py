Here is the translation of the Java code into Python:

```Python
class SearchBaseExtended:
    def __init__(self):
        self.mnemonics = []
        self.ops = []
        self.db = []

    # Holds the masks and values for all the operands.
    class OperandCase:
        def __init__(self, mask=None, value=None, textRep=None, constant=False):
            self.mask = mask
            self.value = value
            self.textRep = textRep
            self.constant = constant

    # Represents a filter for a single instruction. 
    class SLMaskControl:
        def __init__(self, use_mnemonic=True, use_op1=False, use_op2=False, use_const=False):
            self.use_mnemonic = use_mnemonic
            self.use_op1 = use_op1
            self.use_op2 = use_op2
            self.use_const = use_const

    # This is the main method of this class.
    def run(self):
        self.load_selected_instructions()
        self.execute_search()

    # This method runs if you pass in some parameters to it. 
    def run(self, mneonics=None, op1=False, op2=False, constants=False):
        control_list = [SLMaskControl(mneonics, op1, op2, constants)]
        self.load_selected_instructions()
        self.execute_search()

    # This method runs if you pass in a list of SLMaskControls.
    def run(self, controls=None):
        self.control_list = controls
        self.load_selected_instructions()
        self.execute_search()

    # Clears the results. 
    def clear_results(self):
        self.db = []

    # Sets the state for this class.
    def set_state(self, new_state):
        if isinstance(new_state, SLMaskControl):
            self.control_list = [new_state]
        elif isinstance(new_state, list) and all(isinstance(x, SLMaskControl) for x in new_state):
            self.control_list = new_state

    # Loads the selected instructions.
    def load_selected_instructions(self):
        if current_program is None or current_selection is None:
            return
        try:
            logger = SleighDebugLogger(current_program, temp_addr, SleighDebugMode.VERBOSE)
            if logger.parse_failed():
                break
            mask = logger.get_instruction_mask()
            value = logger.get_masked_bytes(mask)
            if mask is None or value is None:
                break

            t_case = Case()
            t_case.mask = mask
            t_case.value = value
            t_case.text_rep = temp_ins.get_mnemonic_string()

            self.mnemonics.append(t_case)

            code_unit = list.get_code_unit_at(temp_addr)
            for x in range(1, logger.get_num_operands() + 1):
                operand_mask = logger.get_operand_value_mask(x - 1)
                operand_value = logger.get_masked_bytes(operand_mask)

                if operand_mask is None or operand_value is None:
                    break

                ot_case = OperandCase()
                ot_case.mask = operand_mask
                ot_case.value = operand_value
                ot_case.text_rep = temp_ins.get_default_operand_representation(x - 1)
                if code_unit.get_scalar(x - 1) is not null:
                    ot_case.constant = True

                if len(self.ops) < x and self.ops > -1:
                    self.ops.append({})

                self.ops[x - 1][t_case] = ot_case
        except Exception as e:
            print(e.message)

    # Performs the application of filters and search instructions for matches.
    def execute_search(self):
        final_search_string = get_final_mask_and_value(self.mnemonics, self.ops, self.control_list)
        value_string = ""
        mask_string = ""

        for element in final_search_string.value:
            value_string += to_hex_string(element) + " "
        for element in final_search_string.mask:
            mask_string += to_hex_string(element) + " "

        print("Final Search Bytes: ")
        print(value_string)
        print("Final Search Mask: ")
        print(mask_string)

        self.find_locations(final_search_string, self.db)

    # Displays results in a table.
    def show(self):
        try:
            if len(self.db) > 0:
                for x in range(len(self.db)):
                    print(f"Address {self.db[x].addr}:")
                    print("Mask: " + to_hex_string(self.db[x].mask))
                    print("Value: " + to_hex_string(self.db[x].value))
        except ImproperUseException as e:
            pass

    # Combines all the masks in the data-structure together into a single byte stream.
    def get_final_mask_and_value(self, mnemonics=None, ops=None, control_list=None):
        if mnemonics is None or ops is None or control_list is None:
            raise Exception("Null Data-Structure")

        for x in range(len(mnemonics)):
            result = build_single_instruction_mask(mnemonics[x], ops, control_list[x])
            masks.append(result.mask)
            values.append(result.value)

    # Populates the database with the locations where the specified byte arrays are found.
    def find_locations(self, search_arrays=None):
        if current_program is None or self.db is None:
            raise Exception("Null Data-Structure")

        for x in range(len(search_arrays)):
            end_address = current_program.get_max_address()
            start_position = current_program.get_min_address()

            while start_position < end_address:
                position = memory.find_bytes(start_position, end_address, search_arrays.value,
                                             search_arrays.mask, True)
                if position is None:
                    break

                temp_case = Case()
                temp_case.mask = search_arrays.mask
                temp_case.value = search_arrays.value
                temp_case.addr = position
                self.db.append(temp_case)

    # Used for determining if there is a "On" bit in a byte stream.
    def contains_on_bit(self, array):
        for element in array:
            value = int.from_bytes(element.encode(), 'big')
            if value != 0:
                return True

        return False

    # Takes two arrays of bytes and performs a bitwise or operation and returns the result.
    def byte_array_or(self, arr1=None, arr2=None):
        if len(arr1) != len(arr2):
            return None
        result = [0] * len(arr1)

        for x in range(len(arr1)):
            result[x] = arr1[x] | arr2[x]

        return result

    # This is the main method of this class.
    def to_hex_string(self, element):
        if isinstance(element, int) or isinstance(element, bytes):
            return format(int.from_bytes(element.encode(), 'big'), 'x')
        else:
            raise Exception("Invalid Type")

# Define a Case object
class Case:
    def __init__(self, mask=None, value=None, text_rep=None):
        self.mask = mask
        self.value = value
        self.textRep = text_rep

# Define an OperandCase class.
class OperandCase(Case):
    def __init__(self, mask=None, value=None, text_rep=None, constant=False):
        super().__init__(mask, value, text_rep)
        self.constant = constant

if __name__ == "__main__":
    search_base_extended = SearchBaseExtended()
    # Call the run method
    search_base_extended.run()

```

Please note that Python does not support direct translation of Java code. The above Python code is a manual translation and may require some adjustments to work correctly in your environment.