class SetCommentsCmd:
    def __init__(self, address: 'Address', pre_comment: str, post_comment: str,
                 eol_comment: str, plate_comment: str, repeatable_comment: str):
        self.address = address
        self.pre_comment = pre_comment
        self.post_comment = post_comment
        self.eol_comment = eol_comment
        self.plate_comment = plate_comment
        self.repeatable_comment = repeatable_comment

    def get_name(self) -> str:
        return "Set Comments"

    @staticmethod
    def comment_changed(new_value: str, old_value: str) -> bool:
        if new_value is None and old_value is None:
            return False
        if new_value is not None:
            return new_value != old_value
        return old_value != new_value

    def apply_to(self, obj):
        program = obj  # assuming DomainObject has a 'program' attribute
        cu = self.get_code_unit(program)

        if cu is not None:
            if self.comment_changed(cu.get_comment(CodeUnit.PRE_COMMENT), self.pre_comment):
                updated_pre_comment = CommentUtils.fixup_annotations(self.pre_comment, program)
                cu.set_comment(CodeUnit.PRE_COMMENT, updated_pre_comment)

            if self.comment_changed(cu.get_comment(CodeUnit.POST_COMMENT), self.post_comment):
                updated_post_comment = CommentUtils.fixup_annotations(self.post_comment, program)
                cu.set_comment(CodeUnit.POST_COMMENT, updated_post_comment)

            if self.comment_changed(cu.get_comment(CodeUnit.EOL_COMMENT), self.eol_comment):
                updated_eol_comment = CommentUtils.fixup_annotations(self.eol_comment, program)
                cu.set_comment(CodeUnit.EOL_COMMENT, updated_eol_comment)

            if self.comment_changed(cu.get_comment(CodeUnit.PLATE_COMMENT), self.plate_comment):
                updated_plate_comment = CommentUtils.fixup_annotations(self.plate_comment, program)
                cu.set_comment(CodeUnit.PLATE_COMMENT, updated_plate_comment)

            if self.comment_changed(cu.get_comment(CodeUnit.REPEATABLE_COMMENT), self.repeatable_comment):
                updated_repeatable_comment = CommentUtils.fixup_annotations(self.repeatable_comment, program)
                cu.set_comment(CodeUnit.REPEATABLE_COMMENT, updated_repeatable_comment)

        return True

    def get_code_unit(self, program: 'Program') -> 'CodeUnit':
        listing = program.get_listing()
        cu = listing.get_code_unit_containing(self.address)
        if cu is None:
            return None
        cu_addr = cu.get_min_address()
        if isinstance(cu, Data) and not self.address.equals(cu_addr):
            data = cu  # assuming Data has a 'get_primitive_at' method
            return data.get_primitive_at(int(self.address.subtract(cu_addr)))
        return cu

    def get_status_msg(self) -> str:
        return self.msg


class CodeUnit:
    PRE_COMMENT = "PRE_COMMENT"
    POST_COMMENT = "POST_COMMENT"
    EOL_COMMENT = "EOL_COMMENT"
    PLATE_COMMENT = "PLATE_COMMENT"
    REPEATABLE_COMMENT = "REPEATABLE_COMMENT"

# Note: You would need to implement the CommentUtils class and its methods
