class MDManagedProperty:
    def __init__(self):
        pass

    def parse_internal(self):
        # Do nothing
        return None

#    def parse_cv_mod(self, dmang) -> None:
#        self.cvmod = MDCVMod(dmang)
#
#    def emit_cv_mod(self, builder: str) -> None:
#        self.cvmod.emit(builder)

class MDManagedPropertyBuilder(MDManagedProperty):
    def __init__(self, dmang):
        super().__init__()
        # Initialize the dmang here

    def parse_internal(self, dmang):
        character_iterator_and_builder = dmang.get_character_iterator_and_builder()
        return None
#
#    def insert(self, builder: str) -> None:
#        if self.modifier_type_name is not None and len(builder) > 0 and builder[0] == ' ':
#            pass
#        else:
#            builder.append_string(self.modifier_type_name)
#
#    def emit(self, builder: str) -> str:
#        result = f"{self.modifier_type_name}"
#        if self.cvmod is not None:
#            modifier_type_builder = StringBuilder()
#            self.emit_cv_mod(modifier_type_builder)
#            insert_space = True
#            if len(builder) > 0 and builder[0] == ' ':
#                insert_space = False
#
#            if len(self.modifier_type_name) != 0:
#                if (self.modifier_type_name[-1] == ' ' or self.modifier_type_name[-1] == '*'):
#                    insert_space = False
#
#            if insert_space:
#                builder.insert(0, ' ')
#
#            if len(self.modifier_type_name) != 0 and self.modifier_type_name[-1] == ' ' and len(builder) > 0 and builder[0] == ' ':
#                self.modifier_type_name = self.modifier_type_name[:-1]
#
#            builder.insert(0, modifier_type_builder)
#
#        if self.mddt is not None:
#            mddt.emit(builder)
#
#        return str(builder)

