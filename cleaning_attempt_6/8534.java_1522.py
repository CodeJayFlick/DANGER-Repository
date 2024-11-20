class BlockCommentsManager:
    BLOCK_INDENT = "    "

    def __init__(self):
        self.block_pre_comments = {}
        self.block_post_comments = {}

    def apply_to(self, program):
        self.apply_to(program, 0)

    def apply_to(self, program, address_delta):
        self.finalize_block_comments(program, address_delta)

    #def begin_block(self, start_address, name, length):
    	#self.symbol_block_nesting_level += 1
    	#self.add_block_comment(start_address, name, length, self.symbol_block_nesting_level)
    	#return self.symbol_block_nesting_level

    #def end_block(self):
    	#if self.symbol_block_nesting_level - 1 < 0:
    	#    raise Exception("Block Nesting went negative")
    	#elif self.symbol_block_nesting_level == 0:
    	#    pass
    	#else:
    	#    return self.symbol_block_nesting_level

    #def get_block_nesting_level(self):
    	#return self.symbol_block_nesting_level

    def add_pre_comment(self, address, pre_comment):
        existing_pre_comment = self.block_pre_comments.get(address)
        if not existing_pre_comment:
            self.block_pre_comments[address] = pre_comment
        else:
            self.block_pre_comments[address] = f"{existing_pre_comment}\n{pre_comment}"

    def add_post_comment(self, address, post_comment):
        existing_post_comment = self.block_post_comments.get(address)
        if not existing_post_comment:
            self.block_post_comments[address] = post_comment
        else:
            self.block_post_comments[address] = f"{post_comment}\n{existing_post_comment}"

    def add_block_comment(self, start_address, name, length, nesting_level):
        indent = ""
        for i in range(nesting_level - 1):
            indent += self.BLOCK_INDENT

        base_comment = f"level {nesting_level}, length {length}"
        if not name:
            pre_comment = f"{indent}PDB: Block Beg, {base_comment}"
        else:
            pre_comment = f"{indent}PDB: Block Beg, ({name}) {base_comment}"

        post_comment = f"{indent}PDB: Block End, {base_comment}"

        self.add_pre_comment(start_address, pre_comment)
        end_address = start_address + length - 1 if length > 0 else 0
        self.add_post_comment(end_address, post_comment)

    def finalize_block_comments(self, program, address_delta):
        for entry in self.block_pre_comments.items():
            append_block_comment(program, entry[0] + address_delta, entry[1], "PRE_ COMMENT")

        for entry in self.block_post_comments.items():
            end_code_unit_address = program.get_listing().get_code_unit_containing(entry[0] + address_delta).get_address()
            append_block_comment(program, end_code_unit_address, entry[1], "POST_COMMENT")


    def append_block_comment(self, program, address, text, comment_type):
        comment = program.get_listing().get_comment(comment_type, address)
        if not comment:
            return f"{text}"
        else:
            return f"{comment}\n{text}"

def create_comment(program, address, comment, comment_type):
    SetCommentCmd.create_comment(program, address, comment, comment_type)

