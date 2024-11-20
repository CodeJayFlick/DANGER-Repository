class EpsilonSymbol:
    def get_fixed_handle(self, hand: 'FixedHandle', walker) -> None:
        hand.space = walker.get_const_space()
        hand.offset_space = None  # Not a dynamic value
        hand.offset_offset = 0
        hand.size = 0  # Cannot provide size

    def print(self, walker) -> str:
        return "0"

    def print_list(self, walker: 'ParserWalker', list: list) -> None:
        list.append(walker.get_parent_handle())

    def restore_xml(self, parser: 'XmlPullParser', sleigh: 'SleighLanguage') -> None:
        element = parser.start("epsilon_sym")
        # Nothing to do
        parser.end(element)
