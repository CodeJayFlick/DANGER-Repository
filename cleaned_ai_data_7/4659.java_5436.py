class DWARFAttributeSpecification:
    def __init__(self, attribute: int, attribute_form: 'DWARFForm'):
        self.attribute = attribute
        self.attribute_form = attribute_form

    @staticmethod
    def read(reader):
        try:
            attribute = reader.read_uint32()
            if attribute == 0:
                return None
            attribute_form = DWARFForm.find(reader.read_uint32())
            return DWARFAttributeSpecification(attribute, attribute_form)
        except Exception as e:
            raise IOException(str(e))

    def get_attribute(self):
        return self.attribute

    def get_attribute_form(self):
        return self.attribute_form

    def __str__(self):
        return f"{DWARFUtil.toString(DWARFAttribute)}->{self.attribute} -> {self.attribute_form}"

    def __hash__(self):
        prime = 31
        result = 1
        result = prime * result + self.attribute
        if self.attribute_form is not None:
            result += self.attribute_form.__hash__()
        return result

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if not isinstance(other, DWARFAttributeSpecification):
            return False
        if self.attribute != other.attribute:
            return False
        if self.attribute_form != other.attribute_form:
            return False
        return True


class IOException(Exception):
    pass

# Note: This code assumes that you have a 'DWARFForm' class and 'DWARFUtil' module in your Python environment.
