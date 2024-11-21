class TestTargetDataTypeMember:
    def __init__(self, parent, key, position, offset, member_name, data_type, type_hint):
        self.parent = parent
        self.key = key
        self.position = position
        self.offset = offset
        self.member_name = member_name
        self.data_type = data_type
        self.type_hint = type_hint

    def change_attributes(self, attributes=None, attribute_map=None):
        if attributes is None:
            attributes = []
        if attribute_map is None:
            attribute_map = {}
        attribute_map.update({
            'position': position,
            'member_name': member_name,
            'offset': offset,
            'data_type': data_type
        })
