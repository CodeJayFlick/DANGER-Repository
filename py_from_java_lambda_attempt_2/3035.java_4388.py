Here is the translation of the given Java code into Python:

```Python
import ghidra.app.script.GhidraScript;
from ghidra.program.model.address import Address;

class FindRunsOfPointersScript(GhidraScript):
    def __init__(self):
        self.results_array = [];
        self.table_array = [];

    @Override
    public void run() throws Exception:
        size = current_program.get_address_factory().get_default_address_space().get_size();
        if (size != 32):
            print("This script only works on 32-bit programs.");
            return;

        search_non_refd = ask_yes_no("", "Would you like to find non-referenced pointer tables?");

        memory = current_program.get_memory();

        distance;
        prev_address = None;
        for addr in memory.get_addresses():
            try:
                if (addr != 0 and memory.contains(addr)):
                    if (prev_address is not None):
                        distance = addr - prev_address
                    else:
                        distance = 0

                    pp = PossiblePtrs(addr, addr, distance)
                    self.results_array.append(pp)

                    prev_address = addr;
            except MemoryAccessException as e:
                break;

        for i in range(len(self.results_array)):
            if (self.results_array[i].get_distance_from_last() == dist):
                table_size += 1
            else:
                if (table_size >= 3):
                    top_address = self.results_array[i - 2].get_addr_of_ptr();
                    ref = find_ref(top_address, distance);
                    pointer_table = Table(top_address, distance, table_size, ref)
                    self.table_array.append(pointer_table)

        print("Table address      Dist bet ptrs     Num ptrs       Ref found");
        for j in range(len(self.table_array)):
            if (self.table_array[j].get_ref() is not None):
                print(f"    {self.table_array[j].get_top_addr()}              {self.table_array[j].get_distance()}                 {self.table_array[j].get_num_pointers()}             at {self.table_array[j].get_ref()}");
            else:
                if (search_non_refd):
                    print(f"    {self.table_array[j].get_top_addr()}              {self.table_array[j].get_distance()}                 {self.table_array[j].get_num_pointers()}             No");

    def find_ref(self, top_address, distance):
        memory = current_program.get_memory();
        ref = None;

        mask_bytes = [0xff] * 4;
        for i in range(4):
            mask_bytes[i] = (memory[address] >> ((24 - (i * 8)) & 0xFF));

        no_ref_found = True;
        try_prev_addr = True;
        long_index = 0;

        while no_ref_found and try_prev_addr:
            test_address = top_address - long_index;
            address_bytes = turn_address_into_bytes(test_address);

            found = memory.find_bytes(current_program.get_min_address(), address_bytes, mask_bytes, True);
            if (found is not None):
                ref = found;
                no_ref_found = False;

        return ref;

    def turn_address_into_bytes(self, addr):
        bytes = [0] * 4;  # only works for 32-bit for now- later add 64
        endian = self.get_endian();

        if (endian == BIG_ENDIAN):
            address_bytes = bytes_forward(addr);
        elif (endian == LITTLE_ENDIAN):
            address_bytes = bytes_reversed(addr);

        return address_bytes;

    def get_endian(self):
        if current_program.language.is_big_endian():
            return 1;  # BIG_ENDIAN
        else:
            return 0;  # LITTLE_ENDIAN

class PossiblePtrs:
    def __init__(self, addr_of_ptr, possible_ptr, distance_from_last):
        self.addr_of_ptr = addr_of_ptr;
        self.possible_ptr = possible_ptr;
        self.distance_from_last = distance_from_last;

    def get_addr_of_ptr(self):
        return self.addr_of_ptr;

    def get_possible_pointer(self):
        return self.possible_ptr;

    def get_distance_from_last(self):
        return self.distance_from_last;

class Table:
    def __init__(self, top_addr, distance, num_pointers, ref):
        self.top_addr = top_addr;
        self.distance = distance;
        self.num_pointers = num_pointers;
        self.ref = ref;

    def get_top_addr(self):
        return self.top_addr;

    def get_distance(self):
        return self.distance;

    def get_num_pointers(self):
        return self.num_pointers;

    def get_ref(self):
        return self.ref;