class DataTypeDecompilerHover:
    NAME = "Data Type Display"
    DESCRIPTION = "Show data type contents when hovering over a type name."
    PRIORITY = 20

    def __init__(self, tool):
        pass

    def get_name(self):
        return self.NAME

    def get_description(self):
        return self.DESCRIPTION

    def get_options_category(self):
        return "CATEGORY_DECOMPILER_POPUPS"

    def get_hover_component(self, program, location, field_location, field):
        if not self.enabled:
            return None
        if not isinstance(field, ClangTextField):
            return None
        token = (field).get_token(field_location)
        dt = self.get_data_type(token)
        if dt is None:
            dt = self.get_data_type(token.parent())
        if dt is not None:
            tool_tip_text = ToolTipUtils().get_tool_tip_text(dt)
            return self.create_tooltip_component(tool_tip_text)
        return None

    def get_data_type(self, node):
        if isinstance(node, ClangVariableDecl):
            return (node).get_data_type()
        elif isinstance(node, ClangReturnType):
            return (node).get_data_type()
        elif isinstance(node, ClangTypeToken):
            return (node).get_data_type()
        elif isinstance(node, ClangVariableToken):
            vn = (node).get_var_node()
            if vn is not None:
                high = vn.get_high()
                if high is not None:
                    return high.get_data_type()
        return None

class ToolTipUtils:
    def get_tool_tip_text(self, dt):
        pass
