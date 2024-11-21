class ConstantPool:
    PRIMITIVE = 0
    STRING_LITERAL = 1
    CLASS_REFERENCE = 2
    POINTER_METHOD = 3
    POINTER_FIELD = 4
    ARRAY_LENGTH = 5
    INSTANCE_OF = 6
    CHECK_CAST = 7

    class Record:
        def __init__(self, tag: int, token: str, value: int):
            self.tag = tag
            self.token = token
            self.value = value
            self.byte_data = None
            self.type = None
            self.is_constructor = False

        def build(self, ref: int, dtmanage) -> str:
            buf = StringBuilder()
            buf.append("<cpoolrec")
            buf.append(f"ref={ref}")
            if self.tag == ConstantPool.STRING_LITERAL:
                buf.append(" tag=\"string\"")
            elif self.tag == ConstantPool.CLASS_REFERENCE:
                buf.append(" tag=\"classref\"")
            elif self.tag == ConstantPool.POINTER_METHOD:
                buf.append(" tag=\"method\"")
            elif self.tag == ConstantPool.POINTER_FIELD:
                buf.append(" tag=\"field\"")
            elif self.tag == ConstantPool.ARRAY_LENGTH:
                buf.append(" tag=\"arraylength\"")
            elif self.tag == ConstantPool.INSTANCE_OF:
                buf.append(" tag=\"instanceof\"")
            elif self.tag == ConstantPool.CHECK_CAST:
                buf.append(" tag=\"checkcast\"")
            else:
                buf.append(" tag=\"primitive\"")

            if self.is_constructor:
                buf.append(f" constructor={self.is_constructor}")

            buf.append(">")

            if self.tag == ConstantPool.PRIMITIVE:
                buf.append("<value>")
                buf.append(str(self.value))
                buf.append("</value>")

            if self.byte_data is not None:
                buf.append("<data length=\"{}\">\n".format(len(self.byte_data)))
                for val in self.byte_data:
                    hi = (val >> 4) & 0xf
                    lo = val & 0xf
                    buf.append(f"{chr(hi + ord('a' if hi > 9 else '0'))}{chr(lo + ord('a' if lo > 9 else '0'))} ")
                buf.append("</data>\n")

            else:
                buf.append("<token>")
                import xml.etree.ElementTree as ET
                ET.SubElement(buf, "token").text = self.token

            dtmanage.build_type_ref(buf, self.type, self.type.get_length())
            buf.append("</cpoolrec>")

        def set_utf8_data(self, val: str):
            self.byte_data = val.encode("UTF-8")
