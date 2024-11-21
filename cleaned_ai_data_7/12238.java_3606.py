class BitFieldPackingImpl:
    def __init__(self):
        self.use_ms_convention = False
        self.type_alignment_enabled = True
        self.zero_length_boundary = 0

    @property
    def use_ms_convention(self):
        return self._use_ms_convention

    @use_ms_convention.setter
    def use_ms_convention(self, value):
        self._use_ms_convention = value

    @property
    def type_alignment_enabled(self):
        return self._type_alignment_enabled

    @type_alignment_enabled.setter
    def type_alignment_enabled(self, value):
        self._type_alignment_enabled = value

    @property
    def zero_length_boundary(self):
        return self._zero_length_boundary

    @zero_length_boundary.setter
    def zero_length_boundary(self, value):
        self._zero_length_boundary = value

    def save_xml(self, buffer):
        if not self.use_ms_convention and self.type_alignment_enabled and self.zero_length_boundary == 0:
            return  # All defaults
        buffer.append("<bitfield_packing>\n")
        if self.use_ms_convention:
            buffer.append("<use_MS_convention value=\"yes\"/>\n")
        if not self.type_alignment_enabled:
            buffer.append("<type_alignment_enabled value=\"no\"/>\n")
        if self.zero_length_boundary != 0:
            buffer.append("<zero_length_boundary value=\"{}\">\n".format(self.zero_length_boundary))
            buffer.append("</zero_length_boundary>\n")
        buffer.append("</bitfield_packing>\n")

    def restore_xml(self, parser):
        while True:
            event = parser.get_event()
            if event == XmlPullParser.END_TAG and parser.get_name() == "bitfield_packing":
                break
            elif event == XmlPullParser.START_TAG and parser.get_name() == "use_MS_convention":
                self.use_ms_convention = bool(parser.get_attribute("value"))
            elif event == XmlPullParser.START_TAG and parser.get_name() == "type_alignment_enabled":
                self.type_alignment_enabled = bool(parser.get_attribute("value"))
            elif event == XmlPullParser.START_TAG and parser.get_name() == "zero_length_boundary":
                self.zero_length_boundary = int(parser.get_attribute("value"))

    def __eq__(self, other):
        if not isinstance(other, BitFieldPackingImpl):
            return False
        if self.type_alignment_enabled != other.type_alignment_enabled:
            return False
        if self.use_ms_convention != other.use_ms_convention:
            return False
        if self.zero_length_boundary != other.zero_length_boundary:
            return False
        return True

    def __hash__(self):
        return (1 + int(self.type_alignment_enabled)) * 5 + self.zero_length_boundary
