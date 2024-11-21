class BitFieldGroupCompositeMember:
    def __init__(self):
        self.list = []

    def is_bit_field_member(self) -> bool:
        return True

    def is_single_bit_field_member(self) -> bool:
        return False

    def is_container(self) -> bool:
        return False

    def is_structure_container(self) -> bool:
        return False

    def is_union_container(self) -> bool:
        return False

    def get_offset(self):
        if not self.list:
            return 0
        return self.list[0].get_offset()

    def get_consumed_bits(self):
        consumed = 0
        for member in self.list:
            consumed += (member.get_data_type().get_bit_size())
        return consumed

    def set_offset(self, offset: int):
        for member in self.list:
            member.set_offset(offset)

    def get_length(self) -> int:
        if not self.list:
            return 0
        return self.list[0].get_length()

    def get_parent(self) -> 'DefaultCompositeMember':
        if not self.list:
            return None
        return self.list[0].get_parent()

    def set_parent(self, new_parent: 'DefaultCompositeMember'):
        for member in self.list:
            member.set_parent(new_parent)

    def add_member(self, member):
        data_type = member.get_data_type()
        if not data_type or data_type.get_length() <= 0:
            return False

        # trigger structure/union transformation
        default_composite_member = self.list.pop(0)
        return default_composite_member.add_member(member)

    def add_to_structure(self, structure):
        success = True
        for member in self.list:
            member.set_bit_field_group(None)
            success &= member.add_to_structure(structure)
        return success

    def finalize_data_type(self, preferred_size: int):
        pass  # nothing to do

    def validate_new_member(self, member) -> 'DefaultCompositeMember':
        if not isinstance(member, DefaultCompositeMember) or not member.is_single_bit_field_member():
            raise ValueError("expected single bit-field member")
        if self.list and (member.get_offset() != self.get_offset() or member.get_length() != self.get_length()):
            raise ValueError(
                "expected bit-field member with same offset and length"
            )
        default_composite_member = DefaultCompositeMember(member)
        default_composite_member.set_bit_field_group(self)
        return default_composite_member

    def add_to_group(self, member):
        self.list.append(self.validate_new_member(member))
