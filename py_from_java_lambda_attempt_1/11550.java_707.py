Here is the translation of the Java code to Python:

```Python
class VarnodeTpl:
    def __init__(self):
        self.space = None
        self.offset = None
        self.size = None

    def __init__(self, space, offset, size):
        self.space = space
        self.offset = offset
        self.size = size

    @property
    def get_space(self):
        return self.space

    @property
    def get_offset(self):
        return self.offset

    @property
    def get_size(self):
        return self.size

    def is_dynamic(self, walker):
        if self.offset.type != 'HANDLE':
            return False
        # Technically we should probably check all three ConstTpls for dynamic handles,
        # but in all cases, if there is any dynamic piece, then the offset is dynamic
        return (walker.get_fixed_handle(self.offset.handle_index).offset_space is not None)

    def is_relative(self):
        return self.offset.type == 'RELATIVE'

    def restore_xml(self, parser, factory):
        el = parser.start('varnode_tpl')
        self.space = ConstTpl()
        self.space.restore_xml(parser, factory)
        self.offset = ConstTpl()
        self.offset.restore_xml(parser, factory)
        self.size = ConstTpl()
        self.size.restore_xml(parser, factory)
        parser.end(el)

    def __str__(self):
        sb = StringBuilder()
        sb.append(str(self.space))
        sb.append('[')
        sb.append(str(self.offset))
        sb.append(':')
        sb.append(str(self.size))
        sb.append(']')
        return str(sb)


class ConstTpl:
    def __init__(self, type='HANDLE'):
        self.type = type

    @property
    def handle_index(self):
        # This method should be implemented in the original Java code,
        # but since it's not provided here, I'm leaving this as a placeholder.
        pass


class ParserWalker:
    def __init__(self):
        pass

    def get_fixed_handle(self, index):
        # This method should be implemented in the original Java code,
        # but since it's not provided here, I'm leaving this as a placeholder.
        pass
```

Please note that Python does not have direct equivalent of Java classes like `XmlElement`, `AddressFactory` and others. Also, some methods are missing implementation details which were present in the original Java code.