class FunctionDataTypeHTMLRepresentation:
    MAX_LINE_COUNT = 10

    def __init__(self, return_type: 'TextLine', function_name: 'TextLine',
                 arguments: list['ValidatableLine'], var_args: 'TextLine', void_args: 'TextLine'):
        self.return_type = return_type
        self.function_name = function_name
        self.arguments = arguments
        self.var_args = var_args
        self.void_args = void_args

        original_html_data = build_html_text(return_type, function_name,
                                               arguments, var_args, void_args, False)
        truncated_html_data = build_html_text(return_type, function_name,
                                               arguments, var_args, void_args, True)

    def __init__(self, function_definition: 'FunctionDefinition'):
        self.return_type = build_return_type(function_definition)
        self.function_name = build_name(function_definition)
        self.arguments = build_arguments(function_definition)
        self.var_args = build_var_args(function_definition)
        self.void_args = build_void_args(function_definition)

        original_html_data = build_html_text(self.return_type, self.function_name,
                                               self.arguments, self.var_args, self.void_args, False)
        truncated_html_data = build_html_text(self.return_type, self.function_name,
                                               self.arguments, self.var_args, self.void_args, True)

    def get_html_string(self):
        return f"<html>{truncated_html_data}</html>"

    def get_html_content_string(self):
        return truncated_html_data

    @staticmethod
    def create_place_holder_line(opposite_line: 'ValidatableLine'):
        if not isinstance(opposite_line, VariableTextLine):
            raise AssertException("I didn't know you could pass me other types of lines?!")
        variable_text_line = opposite_line
        string_length = len(variable_text_line.variable_type) + \
                        len(variable_text_line.variable_name)
        return EmptyVariableTextLine(string_length)

    @staticmethod
    def build_var_args(function_definition: 'FunctionDefinition'):
        if function_definition.has_var_args():
            return TextLine(FunctionSignature.VAR_ARGS_DISPLAY_STRING)
        return TextLine("")

    @staticmethod
    def build_void_args(function_definition: 'FunctionDefinition'):
        if len(function_definition.get_arguments()) == 0 and not function_definition.has_var_args():
            return TextLine(FunctionSignature.VOID_PARAM_DISPLAY_STRING)
        return TextLine("")

    @staticmethod
    def build_name(function_definition: 'FunctionDefinition'):
        return TextLine(HTMLUtilities.friendly_encode_html(function_definition.get_display_name()))

    @staticmethod
    def build_return_type(function_definition: 'FunctionDefinition'):
        data_type = function_definition.get_return_type()
        generic_calling_convention = function_definition.get_generic_calling_convention()
        modifier = f" {generic_calling_convention.get_declaration_name()}" if \
                   generic_calling_convention != GenericCallingConvention.unknown else ""
        return TextLine(f"{HTMLUtilities.friendly_encode_html(data_type.get_display_name())}{modifier}")

    @staticmethod
    def build_arguments(function_definition: 'FunctionDefinition'):
        parameter_definitions = function_definition.get_arguments()
        lines = []
        for var in parameter_definitions:
            data_type = var.get_data_type()
            display_name = data_type.get_display_name()
            name = var.get_name()

            locatable_data_type = get_locatable_data_type(data_type)
            lines.append(VariableTextLine(f"{HTMLUtilities.friendly_encode_html(display_name)}",
                                            f"{HTMLUtilities.friendly_encode_html(name)}", locatable_data_type))
        return lines

    @staticmethod
    def build_html_text(return_type: 'TextLine', function_name: 'TextLine',
                         arguments: list['ValidatableLine'], var_args: 'TextLine', void_args: 'TextLine', trim: bool):
        full_html = StringBuilder()
        truncated_html = StringBuilder()

        line_count = 0
        return_type_text = return_type.get_text()
        if trim:
            return_type_text = StringUtilities.trim_middle(return_type_text, ToolTipUtils.LINE_LENGTH)
        return_type_text = wrap_string_in_color(return_type_text, return_type.get_text_color())

        function_name_text = function_name.get_text()
        if trim:
            function_name_text = StringUtilities.trim_middle(function_name_text, ToolTipUtils.LINE_LENGTH)
        function_name_text = wrap_string_in_color(function_name_text, function_name.get_text_color())

        full_html.append(f"{return_type_text}{HTML_SPACE}{function_name_text}(")
        var_args_text = var_args.get_text()
        has_var_args = len(var_args_text) != 0

        size = len(arguments)
        for i in range(size):
            line_count += 1
            if trim:
                full_html.append(BR)
            else:
                full_html.append(f"{TAB}{arguments[i].get_text()}")
            truncated_html.append(full_html.get_string())

        if has_var_args and size > 0 or len(var_args_text) != 0:
            line_count += 1
            if trim:
                full_html.append(BR)
            else:
                full_html.append(f"{TAB}{var_args_text}")
            truncated_html.append(full_html.get_string())
        elif size == 0:
            void_args_text = void_args.get_text()
            if len(void_args_text) != 0:
                line_count += 1
                if trim:
                    full_html.append(BR)
                else:
                    full_html.append(f"{TAB}{void_args_text}")
                truncated_html.append(full_html.get_string())

        if line_count >= FunctionDataTypeHTMLRepresentation.MAX_LINE_COUNT:
            truncated_html.append(ELLIPSES)

        full_html.append(")").append(BR)
        truncated_html.append(")").append(BR)

        return f"<html>{full_html.get_string()}</html>" if not trim else truncated_html.get_string()

    @staticmethod
    def append(full_html: 'StringBuilder', truncated_html: 'StringBuilder',
               line_count: int, *content):
        for string in content:
            full_html.append(string)
            truncated_html.append(string)

    @staticmethod
    def generate_type_text(line: 'VariableTextLine', trim: bool):
        type = line.get_variable_type()
        if trim:
            type = StringUtilities.trim_middle(type, ToolTipUtils.LINE_LENGTH)
        type = wrap_string_in_color(type, line.get_variable_type_color())

        if not line.has_universal_id():
            return type

        data_type = line.get_data_type()
        url = DataTypeUrl(data_type)
        wrapped = f"{HTMLUtilities.wrap_with_link_placeholder(type, url.toString())}"
        return wrapped

    def diff(self, other_representation: 'FunctionDataTypeHTMLRepresentation'):
        if self == other_representation:
            return [self, self]

        if not isinstance(other_representation, FunctionDataTypeHTMLRepresentation):
            # completely different, make it as such
            return [
                CompletelyDifferentHTMLDataTypeRepresentationWrapper(self),
                CompletelyDifferentHTMLDataTypeRepresentationWrapper(other_representation)
            ]

        function_representation = (FunctionDataTypeHTMLRepresentation) other_representation

        diff_return_type = TextLine(self.return_type.get_text())
        diff_function_name = TextLine(function_representation.function_name.get_text())

        argument_lines = copy_lines(self.arguments)
        var_args_diff = TextLine(var_args.get_text())
        void_args_diff = TextLine(void_args.get_text())

        other_diff_return_type = TextLine(function_representation.return_type.get_text())
        other_diff_function_name = TextLine(function_representation.function_name.get_text())

        other_argument_lines = copy_lines(function_representation.arguments)
        other_var_args_diff = TextLine(var_args.get_text())
        other_void_args_diff = TextLine(void_args.get_text())

        diff_text_line(diff_return_type, other_diff_return_type)
        diff_text_line(diff_function_name, other_diff_function_name)

        html_data_representation_diff_input = HTMLDataTypeRepresentationDiffInput(self, argument_lines)
        other_html_data_representation_diff_input = \
            HTMLDataTypeRepresentationDiffInput(other_representation, other_argument_lines)

        data_type_diff = DataTypeDiffBuilder.diff_body(html_data_representation_diff_input,
                                                         other_html_data_representation_diff_input)

        diff_text_line(var_args_diff, other_var_args_diff)
        diff_text_line(void_args_diff, other_void_args_diff)

        return [
            FunctionDataTypeHTMLRepresentation(diff_return_type, diff_function_name,
                                                 data_type_diff.get_left_lines(), var_args_diff, void_args_diff),
            FunctionDataTypeHTMLRepresentation(other_diff_return_type, other_diff_function_name,
                                                 data_type_diff.get_right_lines(), other_var_args_diff, other_void_args_diff)
        ]

    @staticmethod
    def copy_lines(lines: list['ValidatableLine']):
        new_lines = []
        for line in lines:
            if isinstance(line, VariableTextLine):
                new_line = VariableTextLine(line.variable_type, line.variable_name,
                                             line.get_data_type())
                new_lines.append(new_line)
            else:
                raise AssertException("I didn't know you could pass me other types of lines?!")
        return new_lines

    @staticmethod
    def diff_text_line(left: 'TextLine', right: 'TextLine'):
        if left.get_text() != right.get_text():
            print(f"Left {left.get_text()} vs Right {right.get_text()}")
