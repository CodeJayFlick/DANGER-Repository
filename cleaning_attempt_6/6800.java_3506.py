class ClangBreak:
    def __init__(self, par):
        self.super(par)
        self.indent = 0

    def __init__(self, par, indent):
        self.super(par)
        self.indent = indent

    @property
    def indent(self):
        return self._indent

    def restore_from_xml(self, el, end, pfactory):
        super().restore_from_xml(el, end, pfactory)
        self._indent = int(el.get("indent"))
