class AbstractMemberMsType:
    def __init__(self, pdb=None, name=None, offset=0, field_type_record_number=None, attribute=None):
        self.attribute = attribute
        self.field_type_record_number = field_type_record_number
        self.offset = offset
        self.name = name

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    @property
    def attribute(self):
        return self._attribute

    @attribute.setter
    def attribute(self, value):
        self._attribute = value

    @property
    def field_type_record_number(self):
        return self._field_type_record_number

    @field_type_record_number.setter
    def field_type_record_number(self, value):
        self._field_type_record_number = value

    def emit(self, builder, bind=None):
        if attribute:
            builder.append(str(attribute))
            builder.append(": ")
        my_builder = StringBuilder()
        my_builder.append(name)
        pdb.get_type_record(field_type_record_number).emit(my_builder, None)
        builder.append(str(my_builder))
        builder.append("<@")
        builder.append(str(offset))
        builder.append(">")

class Pdb:
    def get_type_record(self, record_number):
        # implement this method
        pass

class StringBuilder:
    def __init__(self):
        self._builder = ""

    @property
    def text(self):
        return self._builder

    def append(self, value):
        self._builder += str(value)

    def emit(self, builder, bind=None):
        if not self.text.strip():
            return
        builder.append(self.text)
