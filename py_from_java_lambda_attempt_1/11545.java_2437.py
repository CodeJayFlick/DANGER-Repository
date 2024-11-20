Here is the translation of the Java code into Python:

```Python
class VarnodeSymbol:
    def __init__(self):
        self.fix = None

    @property
    def fixed_varnode(self):
        return self.fix

    def get_fixed_handle(self, hand, walker):
        if hasattr(hand, 'space'):
            hand.space = self.fix.space
        hand.offset_space = None  # Not a dynamic variable
        hand.offset_offset = self.fix.offset
        hand.size = self.fix.size

    @property
    def name(self):
        return self.name()

    def print(self, walker):
        return str(self.name)

    def print_list(self, walker, list):
        list.append(walker.get_parent_handle())

    def restore_xml(self, parser, sleigh):
        el = parser.start('varnode_sym')
        if hasattr(el, 'get_attribute'):
            self.fix = VarnodeData()
            factory = sleigh.get_address_factory()
            self.fix.space = factory.get_address_space(el.get_attribute('space'))
            self.fix.offset = int(el.get_attribute('offset'), 0)
            self.fix.size = int(el.get_attribute('size'), 0)
        parser.end(el)


class VarnodeData:
    def __init__(self):
        pass
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. Also, Python does not support method overriding in the same way as Java. The methods are simply redefined with the same name and signature.

Also, Python does not support XML parsing directly like Java's XmlPullParser. You would need to use a library such as xml.etree.ElementTree or lxml for this purpose.