class PostCommentFieldFactory:
    def __init__(self):
        self.FIELD_NAME = "Post-Comment"
        self.GROUP_TITLE = "Format Code"
        self.FIELD_GROUP_TITLE = "Post-comments Field"

    @staticmethod
    def get_auto_post_comment(code_unit):
        if not isinstance(code_unit, Instruction):
            return None

        instruction = code_unit
        override_data = OverrideCommentData()
        flow_override = instruction.get_flow_override()

        if flow_override != FlowOverride.NONE:
            pcode_ops = instruction.get_pcode()
            for op in pcode_ops:
                if op.get_opcode() == PcodeOp.CALL or op.get_opcode() == PcodeOp.CALLOTHER:
                    override_data.set_overriding_ref(instruction.get_program().get_symbol_table().get_primary_symbol(op.get_input(0).get_offset()))
                    break

        return [str(comment) for comment in code_unit.get_comment_as_array(CodeUnit.POST_COMMENT)]

    def get_field(self, proxy_obj, var_width):
        obj = proxy_obj.get_object()
        if not isinstance(obj, CodeUnit) or not self.is_enabled() or not (obj instanceof Data):
            return None

        data = Data(obj)
        if data.get_num_components() > 0:
            return None

        comments = code_unit.get_comment_as_array(CodeUnit.POST_COMMENT)

        if len(comments) == 0 and isinstance(code_unit, Instruction):
            return self.get_text_field(comments, auto_comments=proxy_obj.get_object())

    def get_program_location(self, row, col, listing_field):
        obj = listing_field.get_proxy().get_object()
        if not isinstance(obj, CodeUnit):
            return None

        code_unit = Data(obj)
        comments = code_unit.get_comment_as_array(CodeUnit.POST_COMMENT)

        cpath = None
        if isinstance(code_unit, Data):
            cpath = data.get_component_path()

        return PostCommentFieldLocation(code_unit.get_program(), code_unit.get_min_address(), cpath, row=row, col=col)

    def get_field_location(self, listing_field, index, field_num, program_location):
        if not isinstance(program_location, CommentFieldLocation):
            return None

        comment_type = program_location.get_comment_type()

        if comment_type == CodeUnit.POST_COMMENT:
            return FieldLocation(index=index, field_num=field_num)

    def accepts_type(self, category, proxy_object_class):
        if not issubclass(proxy_object_class, CodeUnit):
            return False
        else:
            return (category == FieldFormatModel.INSTRUCTION_OR_DATA or category == FieldFormatModel.OPEN_DATA)
