class HashStore:
    def __init__(self, function: 'Function', mon):
        self.function = function
        self.program = function.get_program()
        self.monitor = mon
        self.block_list = {}
        self.hash_sort = {}
        self.match_sort = []
        self.matched_block_count = 0
        self.matched_instruction_count = 0
        self.total_instructions = 0

    def get_total_instructions(self):
        return self.total_instructions

    def num_matched_instructions(self):
        return self.matched_instruction_count

    @staticmethod
    def create_block(code_block: 'CodeBlock'):
        block = Block(code_block)
        inst_list = []
        listing = code_block.get_listing()
        for range in code_block:
            cur = range.min_address
            max_ = range.max_address
            while cur <= max_:
                instruct = listing.get_instruction_at(cur)
                if instruct is not None:
                    inst_hash = InstructHash(instruct, block, 0)  # Build Instruction hash container
                    inst_list.append(inst_hash)
                    self.total_instructions += 1
                    cur += instruct.length()
                else:
                    cur += 1
        return Block(block)

    def insert_ngram(self, cur_hash: 'Hash', inst_hash):
        entry = self.hash_sort.get(cur_hash)  # Have we seen this hash before
        if entry is None:  # If not, create a new entry
            entry = HashEntry(cur_hash)
            self.hash_sort[entry] = entry
        else:
            self.match_sort.remove(entry)

        entry.inst_list.append(inst_hash)  # add the new n-gram

    def insert_instruction_ngrams(self, inst_hash):
        for i in range(len(inst_hash.n_grams)):
            cur_hash = inst_hash.n_grams[i]
            if cur_hash is not None:
                self.insert_ngram(cur_hash, inst_hash)

    @staticmethod
    def remove_ngram(inst_hash: 'InstructHash', cur_hash):
        entry = inst_hash.hash_entries.get(cur_hash)
        if entry is not None:
            self.match_sort.remove(entry)  # Remove from matchSort before modifying instList

    def remove_instruction_ngrams(self, inst_hash):
        for i in range(len(inst_hash.n_grams)):
            cur_hash = inst_hash.n_grams[i]
            if cur_hash is not None:
                entry = inst_hash.hash_entries.get(cur_hash)
                self.match_sort.remove(entry)  # Remove from matchSort before modifying instList
                if len(entry.inst_list) == 0:
                    del self.hash_sort[entry]

    def remove_hash(self, hash_entry):
        self.match_sort.remove(hash_entry)

    @staticmethod
    def calc_hashes(min_length: int, max_length: int, whole_block: bool, match_only: bool, hash_calculator):
        for block in self.block_list.values():
            block.calc_hashes(min_length, max_length, whole_block, match_only, hash_calculator)

    def insert_hashes(self):
        for block in self.block_list.values():
            for i in range(len(block.inst_list)):
                inst_hash = block.inst_list[i]
                if not inst_hash.is_matched:
                    self.insert_instruction_ngrams(inst_hash)
                    break

    @staticmethod
    def extend_match(n_gram_size: int, src_instruct: 'InstructHash', src_match, dest_instruct: 'InstructHash',
                     dest_match, hash_calculator):
        while src_match.start_index > 0 and dest_match.start_index > 0:
            cur_src_instruct = src_match.block.inst_list[src_match.start_index - 1]
            cur_dest_instruct = dest_match.block.inst_list[dest_match.start_index - 1]

    def get_unmatched_instructions(self):
        res = []
        for block in self.block_list.values():
            for inst_hash in block.inst_list:
                if not inst_hash.is_matched:
                    res.append(inst_hash.instruction)
        return res

    @staticmethod
    def clear_sort(hash_sort, match_sort):
        hash_sort.clear()
        match_sort.clear()

    def is_empty(self):
        return len(self.match_sort) == 0

    def get_first_entry(self):
        if self.is_empty():
            return None
        else:
            return self.match_sort[0]

    @staticmethod
    def get_entry(hash, hash_sort):
        return hash_sort.get(hash)

    @staticmethod
    def get_block(addr: 'Address'):
        return block_list.get(addr)
