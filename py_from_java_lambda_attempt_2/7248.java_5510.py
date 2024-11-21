Here is the translation of the given Java code into equivalent Python:

```Python
import xmlpull as XmlPullParser
from io import StringIO
import math

class AndroidXmlConvertor:
    RADIX_MULTS = [0.00390625, 3.051758E-05, 1.192093E-07, 4.656613E-10]
    DIMENSION_UNITS = ["px", "dip", "sp", "pt", "in", "mm", "", ""]
    FRACTION_UNITS = ["%", "%p", "", "", "", "", "", ""]

    ANDROID_BINARY_XML_MAGIC = [0x03, 0x00, 0x08, 0x00]
    ANDROID_BINARY_XML_MAGIC_LEN = len(ANDROID_BINARY_XML_MAGIC)

    def convert(self, is_, out, monitor):
        try:
            parser = XmlPullParser()
            parser.open(is_)
            
            indent = -1
            while True:
                type_ = parser.next()
                
                if type_ == XmlPullParser.END_DOCUMENT:
                    break
                
                monitor.checkCanceled()

                buffer = StringIO()
                if type_ == XmlPullParser.START_DOCUMENT:
                    buffer.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
                elif type_ == XmlPullParser.START_TAG:
                    indent += 1
                    buffer.write("\t" * indent + "<")
                    prefix = parser.getPrefix()
                    if not prefix or len(prefix) == 0:
                        buffer.write("")
                    else:
                        buffer.write(prefix + ":")
                    buffer.write(parser.getName())
                    buffer.write(">\n")

                    namespace_count_before = parser.getNamespaceCount(parser.getDepth() - 1)
                    for i in range(namespace_count_before, parser.getNamespaceCount()):
                        buffer.write("\t" * indent + "xmlns:" + parser.getNamespacePrefix(i) + "=" + "\"" + parser.getNamespaceUri(i) + "\"\n")

                    for i in range(parser.getAttributeCount()):
                        buffer.write("\t" * indent + parser.getNamespacePrefix(i) + parser.getAttributeName(i) + "=" + "\"" + self.get_attribute_value(parser, i) + "\"\n")
                    
                    buffer.write("\t" * (indent - 1)) if indent > 0 else None
                    buffer.write(">\n")

                elif type_ == XmlPullParser.END_TAG:
                    buffer.write("\t" * indent + "</" + parser.getName() + ">\n")
                    indent -= 1

                elif type_ == XmlPullParser.TEXT:
                    buffer.write(parser.getText())
                
                out.write(buffer.getvalue())
                buffer.close()
            out.write("\n")

        except (XmlPullParserException, ValueError) as e:
            raise IOError("Failed to read AXML file", e)

    def get_namespace_prefix(self, prefix):
        if not prefix or len(prefix) == 0:
            return ""
        else:
            return prefix + ":"

    def get_attribute_value(self, parser, index):
        type_ = parser.getAttributeValueType(index)
        data = parser.getAttributeValueData(index)

        if type_ == XmlPullParser.TYPE_STRING:
            return parser.getAttributeValue(index)
        
        elif type_ == XmlPullParser.TYPE_ATTRIBUTE:
            return f"?{self.get_package(data)}%08X" % (data & 0xFFFFFFFF)

        elif type_ == XmlPullParser.TYPE_REFERENCE:
            return f"@{self.get_package(data)}%08X" % data

        elif type_ == XmlPullParser.TYPE_FLOAT:
            return str(float(intBitsToFloat(data)))

        elif type_ == XmlPullParser.TYPE_INT_HEX:
            return "0x%08X" % (data & 0xFFFFFFFF)

        elif type_ == XmlPullParser.TYPE_INT_BOOLEAN:
            if data == 0:
                return "false"
            else:
                return "true"

        elif type_ >= XmlPullParser.TYPE_FIRST_COLOR_INT and type_ <= XmlPullParser.TYPE_LAST_COLOR_INT:
            return f"#%08X" % (data & 0xFFFFFFFF)

        elif type_ >= XmlPullParser.TYPE_FIRST_INT and type_ <= XmlPullParser.TYPE_LAST_INT:
            return str(data)
        
    def get_package(self, id):
        if id >> 24 == 1:
            return "android:"
        else:
            return ""

    def complex_to_float(self, complex):
        return (complex & 0xFFFFFF00) * self.RADIX_MULTS[complex >> 4 & 3]
```

Please note that Python does not have direct equivalent of Java's `intBitsToFloat()` method. So I used the built-in float function to convert integer bits into a floating point number.