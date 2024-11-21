class XmlElement:
    def __init__(self):
        pass

class XmlElementImpl(XmlElement):
    def __init__(self, is_start: bool, is_end: bool, name: str, level: int,
                 attributes: dict or None, text: str or None, column_number: int, line_number: int) -> None:
        if is_start and is_end:
            raise XmlException("empty elements must be split into separate start and end elements (see split_empty_element)")
        
        self.name = name
        self.level = level
        self.attributes = attributes.copy() if attributes else {}
        self.text = text or ""
        self.is_start = is_start
        self.is_end = is_end
        self.is_content = not (is_start and is_end)
        self.column_number = column_number
        self.line_number = line_number

    def get_column_number(self) -> int:
        return self.column_number

    def get_line_number(self) -> int:
        return self.line_number

    def has_attribute(self, key: str) -> bool:
        if not self.attributes:
            return False
        return key in self.attributes

    def get_attribute(self, key: str) -> str or None:
        if not self.attributes:
            return None
        return self.attributes.get(key)

    def get_attributes(self) -> dict or None:
        return self.attributes.copy() if self.attributes else {}

    def set_attribute(self, key: str, value: str) -> None:
        self.attributes[key] = value

    def get_level(self) -> int:
        return self.level

    def get_name(self) -> str:
        return self.name

    def get_text(self) -> str or None:
        return self.text

    def is_content(self) -> bool:
        return self.is_content

    def is_end(self) -> bool:
        return self.is_end

    def is_start(self) -> bool:
        return self.is_start

    def __str__(self) -> str:
        sb = StringBuilder()

        if self.is_content:
            if not self.text:
                sb.append("(null)")
            else:
                sb.append(self.text.replace("\n", "\\n"))
        elif self.is_start:
            sb.append("<")
            sb.append(self.name)
            sb.append("(")
            sb.append(str(self.level))
            sb.append(")")

            sep = "  "
            if self.attributes:
                for attribute in self.attributes.items():
                    sb.append(sep)
                    sb.append(attribute[0])
                    sb.append("=")
                    sb.append(f'"{attribute[1]}"')
        elif self.is_end:
            if not self.text:
                sb.append("(null)")
            else:
                sb.append(self.text.replace("\n", "\\n"))
            sb.append("</")
            sb.append(self.name)
            sb.append("(")
            sb.append(str(self.level))
            sb.append(")")

        sb.append(f" @{self.line_number}:{self.column_number}")

        return str(sb)

    @staticmethod
    def split_empty_element(element: XmlElementImpl) -> list:
        if element.is_start() and element.is_end():
            result = [
                XmlElementImpl(True, False, element.get_name(), element.get_level(),
                                element.get_attributes(), None, element.get_column_number(),
                                element.get_line_number()),
                XmlElementImpl(False, True, element.get_name(), element.get_level(), None,
                               "", element.get_column_number(), element.get_line_number())
            ]
        else:
            result = [element]

        return result

class XmlException(Exception):
    pass
