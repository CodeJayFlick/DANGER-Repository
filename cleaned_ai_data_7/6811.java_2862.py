class ClangStatement:
    def __init__(self):
        self.op = None  # Root op of C-statement

    @property
    def pcode_op(self):
        return self.op

    def restore_from_xml(self, parser, pfactory):
        node = next(parser)
        if 'opref' in node.attrib:
            ref_id = int(node.attrib['opref'])
            self.op = pfactory.get_op_ref(ref_id)
