Here is the translation of the given Java code into equivalent Python:

```Python
class PrettyPrinter:
    INDENT_STRING = "  "

    def __init__(self, function: 'Function', tokgroup: 'ClangTokenGroup') -> None:
        self.function = function
        self.tokgroup = tokgroup
        self.lines = DecompilerUtils.to_lines(tokgroup)
        self.pad_empty_lines()

    def pad_empty_lines(self) -> None:
        for line in self.lines:
            token_list = line.get_all_tokens()
            if len(token_list) == 0:
                spacer_token = ClangToken.build_spacer(None, line.get_indent(), self.INDENT_STRING)
                spacer_token.set_line_parent(line)
                token_list.insert(0, spacer_token)

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, value: 'Function'):
        self._function = value

    @property
    def lines(self) -> list:
        return self._lines

    @lines.setter
    def lines(self, value: list):
        self._lines = value

    def print(self, remove_invalid_chars: bool) -> 'DecompiledFunction':
        buff = StringBuffer()

        for line in self.lines:
            buff.append(line.get_indent_string())
            tokens = line.get_all_tokens()
            for token in tokens:
                if isinstance(token, (ClangFuncNameToken, ClangVariableToken, ClangTypeToken, ClangFieldToken, ClangLabelToken)):
                    is_token2_clean = True
                    # do not clean constant variable tokens
                    if token.get_syntax_type() == ClangToken.CONST_COLOR and isinstance(token, (ClangFuncNameToken, ClangVariableToken, ClangTypeToken, ClangFieldToken, ClangLabelToken)):
                        is_token2_clean = False

                    if remove_invalid_chars and is_token2_clean:
                        token_text = token.get_text()
                        for i in range(len(token_text)):
                            if StringUtilities.is_valid_c_language_char(token_text[i]):
                                buff.append(token_text[i])
                            else:
                                buff.append('_')
                    else:
                        buff.append(token.get_text())
                buff.append(StringUtilities.LINE_SEPARATOR)

        return DecompiledFunction(self.find_signature(), str(buff))

    def find_signature(self) -> str:
        n_children = self.tokgroup.num_children()
        for i in range(n_children):
            node = self.tokgroup.child(i)
            if isinstance(node, ClangFuncProto):
                return f"{node.get_text()};"
        return None

class StringBuffer:
    def __init__(self) -> None:
        self.buffer = ""

    def append(self, text: str) -> None:
        self.buffer += text
```

Note that the above Python code is a direct translation of your given Java code.