import xml.sax as sax

class SpecXmlUtils:
    @staticmethod
    def decode_boolean(val):
        if val and len(val) > 0:
            switcher = {
                'y': True,
                't': True,
                '1': True,
                'n': False,
                'f': False,
                '0': False
            }
            return switcher.get(val[0].lower(), False)

    @staticmethod
    def encode_boolean(val):
        if val:
            return "true"
        else:
            return "false"

    @staticmethod
    def encode_string_attribute(buf, nm, val):
        buf.append('  ')
        buf.append(nm)
        buf.append("=\"")
        buf.append(val)
        buf.append("\"")

    @staticmethod
    def encode_signed_integer(val):
        return str(long(val))

    @staticmethod
    def encode_unsigned_integer(val):
        return "0x" + hex(int(val))[2:]

    @staticmethod
    def encode_signed_integer_attribute(buf, nm, val):
        buf.append('  ')
        buf.append(nm)
        buf.append("=\"")
        buf.append(SpecXmlUtils.encode_signed_integer(val))
        buf.append("\"")

    @staticmethod
    def encode_unsigned_integer_attribute(buf, nm, val):
        buf.append('  ')
        buf.append(nm)
        buf.append("=\"")
        buf.append(SpecXmlUtils.encode_unsigned_integer(val))
        buf.append("\"")

    @staticmethod
    def encode_double_attribute(buf, nm, val):
        buf.append('  ')
        buf.append(nm)
        buf.append("=\"")
        buf.append(str(float(val)))
        buf.append("\"")

    @staticmethod
    def decode_int(int_string):
        if int_string is None:
            return 0

        # special case
        if "0".equals(int_string):
            return 0

        bi = None
        if int_string.startswith("0x"):
            bi = long(hex(long(str(int(int_string[2:], 16))))[2:])
        elif int_string.startswith("0"):
            bi = long(oct(long(str(int(int_string[1:], 8))))[2:])
        else:
            bi = long(str(int(int_string, 10)))

        return bi

    @staticmethod
    def decode_long(long_string):
        if long_string is None:
            return 0

        # special case
        if "0".equals(long_string):
            return 0

        bi = None
        if long_string.startswith("0x"):
            bi = long(hex(long(str(int(long_string[2:], 16))))[2:])
        elif long_string.startswith("0"):
            bi = long(oct(long(str(int(long_string[1:], 8)))[2:])
        else:
            bi = long(str(int(long_string, 10)))

        return bi

    @staticmethod
    def xml_escape(buf, val):
        for i in range(len(val)):
            c = val[i]
            if c <= '>':
                switcher = {
                    '&': "&amp;",
                    '<': "&lt;",
                    '>': "&gt;",
                    '"': "&quot;",
                    "'": "&apos;"
                }
                buf.append(switcher.get(c, str(c)))
            else:
                buf.append(str(c))

    @staticmethod
    def xml_escape_attribute(buf, nm, val):
        buf.append('  ')
        buf.append(nm)
        buf.append("=\"")
        SpecXmlUtils.xml_escape(buf, val)
        buf.append("\"")

    @staticmethod
    def xml_escape_writer(writer, val):
        for i in range(len(val)):
            c = val[i]
            if c == '&':
                writer.write("&amp;")
            elif c == '<':
                writer.write("&lt;")
            elif c == '>':
                writer.write("&gt;")
            elif c == '"':
                writer.write("&quot;")
            elif c == "'":
                writer.write("&apos;")
            else:
                writer.write(str(c))

    @staticmethod
    def get_xml_handler():
        return sax.ErrorHandler()
