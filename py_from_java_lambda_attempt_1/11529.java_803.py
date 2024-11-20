Here is the translation of the Java code into Python:

```Python
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
```

Note that Python does not have direct equivalents for Java's `@Override` and package-level imports. The `get_fixed_handle`, `print`, `print_list`, and `restore_xml` methods are equivalent to the corresponding methods in the original Java code, but with some differences due to the nature of Python (e.g., no need for explicit type declarations).