Here is the translation of the given Java code into equivalent Python:

```Python
class ClangXML:
    DOCUMENT = "clang_document"
    FUNCTION = "function"
    BLOCK = "block"
    RETURN_TYPE = "return_type"
    VARDECL = "vardecl"
    STATEMENT = "statement"
    FUNCPROTO = "funcproto"
    SYNTAX = "syntax"
    BREAK = "break"
    VARIABLE = "variable"
    OP = "op"
    FUNCNAME = "funcname"
    TYPE = "type"
    FIELD = "field"
    COMMENT = "comment"
    LABEL = "label"

    INDENT = "indent"
    COLOR = "color"
    OPREF = "opref"
    BLOCKREF = "blockref"
    VARNODEREF = "varref"
    SPACE = "space"
    OFFSET = "off"
    PCSPACE = "pcspace"
    PCOFFSET = "pcoff"
    SYMREF = "symref"

    KEYWORD_COLOR = "keyword"
    COMMENT_COLOR = "comment"
    TYPE_COLOR = "type"
    FUNCNAME_COLOR = "funcname"
    VARIABLE_COLOR = "var"
    CONST_COLOR = "const"
    PARAMETER_COLOR = "param"
    GLOBAL_COLOR = "global"


def build_clang_tree(parser, hfunc):
    docroot = None
    if parser.peek().tag == FUNCTION:
        docroot = ClangFunction(None, hfunc)
    else:
        docroot = ClangTokenGroup(None)

    docroot.restore_from_xml(parser, hfunc)
    return docroot


class ClangFunction:
    def __init__(self, parent, high_function):
        self.parent = parent
        self.high_function = high_function

    # method to restore from XML parser and high function
    def restore_from_xml(self, parser, high_function):
        pass


class ClangTokenGroup:
    def __init__(self, parent):
        self.parent = parent

    # method to restore from XML parser and high function
    def restore_from_xml(self, parser, high_function):
        pass
```

Please note that the above Python code is a direct translation of the given Java code. However, it does not include any implementation details for methods like `restoreFromXML` in classes `ClangFunction` and `ClangTokenGroup`.