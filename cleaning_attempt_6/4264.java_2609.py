class CommentFieldSearcher:
    def __init__(self, program: 'ghidra.program.model.Program', start_loc: 'ghidra.program.model.location.ProgramLocation',
                 set_view: 'ghidra.program.model.address.AddressSetView', forward: bool,
                 pattern: re.Pattern, comment_type: int):
        self.comment_type = comment_type
        self.program = program
        super().__init__(pattern, forward, start_loc, set_view)
        
        if set_view is not None:
            iterator = program.get_listing().get_comment_address_iterator(comment_type, set_view, forward)
        else:
            address_set = program.get_memory()
            if forward:
                address_set.intersect_range(start_loc.get_address(), address_set.max_address())
            else:
                address_set.intersect_range(address_set.min_address(), start_loc.get_address())
            
            iterator = program.get_listing().get_comment_address_iterator(comment_type, address_set, forward)

    def advance(self, current_matches: list) -> 'ghidra.program.model.location.ProgramLocation':
        next_address = self.iterator.next()
        
        if next_address is not None:
            find_matches_for_current_address(next_address, current_matches)
            
        return next_address

    def find_matches_for_current_address(self, address: 'ghidra.program.model.address.Address',
                                          current_matches: list):
        comment = self.program.get_listing().get_comment(self.comment_type, address)
        
        if comment is None:
            return
        
        cleaned_up_comment = comment.replace('\n', ' ')
        matcher = pattern.matcher(cleaned_up_comment)
        
        while matcher.find():
            index = matcher.start()
            current_matches.append(get_comment_location(comment, index, address))

    def get_comment_location(self, comment_str: str, index: int, address: 'ghidra.program.model.address.Address') -> 'CommentFieldLocation':
        comments = StringUtilities.to_lines(comment_str)
        
        row_index = find_row_index(comments, index)
        char_offset = find_char_offset(index, row_index, comments)
        
        data_path = get_data_component_path(address)
        
        if self.comment_type == CodeUnit.EOL_COMMENT:
            return EolCommentFieldLocation(self.program, address, data_path, comments, row_index, char_offset, row_index)
        elif self.comment_type == CodeUnit.PLATE_COMMENT:
            return PlateFieldLocation(self.program, address, data_path, row_index, char_offset, comments, row_index)
        elif self.comment_type == CodeUnit.REPEATABLE_COMMENT:
            # TODO One of searchStrIndex parameters is wrong.
            return RepeatableCommentFieldLocation(self.program, address, data_path, comments, row_index, char_offset, row_index)
        else:  # self.comment_type == CodeUnit.POST_COMMENT
            return PostCommentFieldLocation(self.program, address, data_path, comments, row_index, char_offset)

    def get_data_component_path(self, address: 'ghidra.program.model.address.Address') -> list:
        cu = self.program.get_listing().get_code_unit_containing(address)
        
        if cu is None:
            return []
        
        if isinstance(cu, Data):
            data = cu
            primitive_at = data.get_primitive_at(int(address.subtract(data.get_address())))
            
            if primitive_at is not None:
                return primitive_at.get_component_path()
        
        return []

    def find_char_offset(self, index: int, row_index: int, op_strings: list) -> int:
        total_before_op_index = 0
        
        for i in range(row_index):
            total_before_op_index += len(op_strings[i])
        
        return index - total_before_op_index

    def find_row_index(self, comment_strings: list, index: int) -> int:
        total_so_far = 0
        
        for i in range(len(comment_strings)):
            if index < total_so_far + len(comment_strings[i]):
                return i
            
            total_so_far += len(comment_strings[i])
        
        return len(comment_strings) - 1
