class InjectPayloadSegment:
    def __init__(self, source):
        self.type = "EXECUTABLEPCODE_ TYPE"
        self.space = None
        self.supports_far_pointer = False
        self.const_resolve_space = None
        self.const_resolve_offset = 0
        self.const_resolve_size = 0

    def save_xml(self, buffer):
        buffer.append("<segmentop>")
        pos = name.find("_")
        sub_name = name[:pos] if pos > 0 else name
        if not sub_name == "segment":
            SpecXmlUtils.encode_string_attribute(buffer, "userop", sub_name)
        SpecXmlUtils.encode_string_attribute(buffer, "space", self.space.name)
        if self.supports_far_pointer:
            buffer.append("farpointer")
        buffer.append(">\n")
        super().save_xml(buffer)
        if self.const_resolve_space is not None:
            buffer.append("<constresolve>")
            buffer.append("<varnode")
            SpecXmlUtils.encode_string_attribute(buffer, "space", self.const_resolve_space.name)
            SpecXmlUtils.encode_unsigned_integer_attribute(buffer, "offset", self.const_resolve_offset)
            SpecXmlUtils.encode_signed_integer_attribute(buffer, "size", self.const_resolve_size)
            buffer.append("/>\n")
            buffer.append("</constresolve>\n")
        buffer.append("</segmentop>\n")

    def restore_xml(self, parser, language):
        el = parser.start()
        name = el.get("userop")
        if not name:
            name = "segment"
        self.name = name + "_pcode"
        space_string = el.get("space")
        self.space = language.get_address_factory().get_address_space(space_string)
        if self.space is None:
            raise XmlParseException(f"Unknown address space: {space_string}")
        self.supports_far_pointer = SpecXmlUtils.decode_boolean(el.get("farpointer"))
        if parser.peek() == "pcode":
            super().restore_xml(parser, language)

    def __eq__(self, obj):
        op2 = InjectPayloadSegment(obj)
        return (op2.const_resolve_offset == self.const_resolve_offset and
                op2.const_resolve_size == self.const_resolve_size and
                SystemUtilities.is_equal(self.const_resolve_space, op2.const_resolve_space) and
                self.space == op2.space and
                self.supports_far_pointer == op2.supports_far_pointer)

    def __hash__(self):
        hash = self.space.__hash__()
        if self.const_resolve_space is not None:
            hash *= 79 + self.const_resolve_space.__hash__()
        hash *= 79 + long(self.const_resolve_offset).__hash__()
        hash *= 79 + self.const_resolve_size
        return hash * (1 if self.supports_far_pointer else 13)
