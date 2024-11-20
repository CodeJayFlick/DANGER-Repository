class ContextChange:
    def apply(self, walker: 'ParserWalker', debug: 'SleighDebugLogger') -> None:
        pass  # Implement this method in your subclass.

    def restore_xml(self, parser: 'XmlPullParser', lang: 'SleighLanguage') -> None:
        pass  # Implement this method in your subclass.
