class BackwardsSliceToPCodeOpsAction:
    def __init__(self):
        super().__init__("Highlight Backward Operator Slice")
        self.set_help_location(HelpLocation("DECOMPILER", "ActionHighlight"))
        self.set_popup_menu_data(["Highlight", "Backward Operator Slice"], "Decompile")

    def is_enabled_for_decompiler_context(self, context):
        token_at_cursor = context.get_token_at_cursor()
        varnode = DecompilerUtils().get_varnode_ref(token_at_cursor)
        return varnode is not None

    def decompiler_action_performed(self, context):
        token_at_cursor = context.get_token_at_cursor()
        varnode = DecompilerUtils().get_varnode_ref(token_at_cursor)
        if varnode is not None:
            op = token_at_cursor.get_pcode_op()
            backward_slice = DecompilerUtils().get_backward_slice_to_p_code_ops(varnode)
            if op is not None:
                backward_slice.add(op)
            decompiler_panel = context.get_decompiler_panel()
            decompiler_panel.clear_primary_highlights()
            decompiler_panel.add_pcode_op_highlights(backward_slice, decompiler_panel.get_current_variable_highlight_color())
