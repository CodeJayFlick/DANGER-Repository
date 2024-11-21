class AbstractIndirectVirtualBaseClassMsType:
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def direct_virtual_base_class_record_number(self):
        return self._direct_virtual_base_class_record_number

    @direct_virtual_base_class_record_number.setter
    def direct_virtual_base_class_record_number(self, value):
        self._direct_virtual_base_class_record_number = value

    @property
    def virtual_base_pointer_record_number(self):
        return self._virtual_base_pointer_record_number

    @virtual_base_pointer_record_number.setter
    def virtual_base_pointer_record_number(self, value):
        self._virtual_base_pointer_record_number = value

    @property
    def attribute(self):
        return self._attribute

    @attribute.setter
    def attribute(self, value):
        self._attribute = value

    @property
    def virtual_base_pointer_offset_from_address_point(self):
        return self._virtual_base_pointer_offset_from_address_point

    @virtual_base_pointer_offset_from_address_point.setter
    def virtual_base_pointer_offset_from_address_point(self, value):
        self._virtual_base_pointer_offset_from_address_point = value

    @property
    def virtual_base_offset_from_vb_table(self):
        return self._virtual_base_offset_from_vb_table

    @virtual_base_offset_from_vb_table.setter
    def virtual_base_offset_from_vb_table(self, value):
        self._virtual_base_offset_from_vb_table = value

    def emit(self, builder, bind):
        builder.append("<indirect ")
        builder.append(str(self.attribute))
        builder.append(": ")
        type = self.pdb.get_type_record(self.direct_virtual_base_class_record_number)
        builder.append(type.name)

        vbp_builder = StringBuilder()
        vbp_builder.append("vbp")
        self.pdb.get_type_record(self.virtual_base_pointer_record_number).emit(vbp_builder, Bind.NONE)
        builder.append(str(vbp_builder))
        builder.append("; offVbp=" + str(self.virtual_base_pointer_offset_from_address_point) +
                    "; offVbte=" + str(self.virtual_base_offset_from_vb_table) + "; >")

    def get_base_pointer_offset(self):
        return self.virtual_base_pointer_offset_from_address_point

    def get_base_offset_from_vbt(self):
        return self.virtual_base_offset_from_vb_table

    def get_attributes(self):
        return self.attribute

    def get_base_class_record_number(self):
        return self.direct_virtual_base_class_record_number

    def get_virtual_base_pointer_record_number(self):
        return self.virtual_base_pointer_record_number
