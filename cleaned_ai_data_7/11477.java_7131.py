class ContextCommit:
    def __init__(self):
        self.sym = None
        self.num = 0
        self.mask = 0

    def apply(self, walker, debug=None) -> None:
        if debug is not None:
            debug.dump_global_set(walker.get_parser_context(), walker.get_state(), self.sym, self.num, self.mask)
        walker.get_parser_context().add_commit(walker.get_state(), self.sym, self.num, self.mask)

    def restore_xml(self, parser: XmlPullParser, lang) -> None:
        el = parser.start("commit")
        id = int(el.get_attribute("id"))
        self.sym = lang.get_symbol_table().find_symbol(id)
        self.num = int(el.get_attribute("num"))
        self.mask = int(el.get_attribute("mask"))
        parser.end(el)

