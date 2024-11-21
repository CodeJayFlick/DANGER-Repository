class AbstractModifierMsType:
    def __init__(self, pdb, modified_record_number=None):
        self.pdb = pdb
        if modified_record_number is None:
            self.modified_record_number = None
        else:
            self.modified_record_number = modified_record_number

    @property
    def is_const(self):
        return hasattr(self, 'is_const')

    @is_const.setter
    def is_const(self, value):
        self.__setattr__('is_const', value)

    @property
    def is_volatile(self):
        return hasattr(self, 'is_volatile')

    @is_volatile.setter
    def is_volatile(self, value):
        self.__setattr__('is_volatile', value)

    @property
    def is_unaligned(self):
        return hasattr(self, 'is_unaligned')

    @is_unaligned.setter
    def is_unaligned(self, value):
        self.__setattr__('is_unaligned', value)

    def get_modified_record_number(self):
        return self.modified_record_number

    def get_modified_type(self):
        if self.modified_record_number:
            return self.pdb.get_type_record(self.modified_record_number)
        else:
            return None

    def emit(self, builder, bind):
        mod_builder = StringBuilder()
        if hasattr(self, 'is_const'):
            mod_builder.append('const ')
        if hasattr(self, 'is_volatile'):
            mod_builder.append('volatile ')
        if hasattr(self, 'is_unaligned'):
            mod_builder.append('__unaligned ')
        if self.modified_record_number:
            mod_builder.append(str(self.get_modified_type()))
        else:
            mod_builder.append('')
        builder.insert(0, str(mod_builder))

    def process_attributes(self, atts):
        self.is_const = (atts & 1) == 1
        atts >>= 1
        self.is_volatile = (atts & 1) == 1
        atts >>= 1
        self.is_unaligned = (atts & 1) == 1


class Pdb:
    def __init__(self):
        pass

    def get_type_record(self, record_number):
        # This method should return the type record based on the given record number.
        pass
