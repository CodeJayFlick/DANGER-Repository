class EndInstructionValue:
    HASH = "[inst_next]".hash()

    def __eq__(self, obj):
        return isinstance(obj, EndInstructionValue)

    def __hash__(self):
        return self.HASH

    @property
    def min_value(self):
        return 0

    @property
    def max_value(self):
        return 0

    def get_value(self, walker) -> int:
        addr = walker.get_naddr()
        return addr.addressable_word_offset()

    def restore_xml(self, parser: XmlPullParser, lang: SleighLanguage):
        parser.discard_subtree("end_exp")
        # Nothing to do
        pass

    def __str__(self):
        return "[inst_next]"
