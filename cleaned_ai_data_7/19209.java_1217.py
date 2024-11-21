class YggdrasilSerializer:
    def serialize(self, o):
        if isinstance(o, YggdrasilExtendedSerializable):
            return o.serialize()
        else:
            return Fields(o)

    def deserialize(self, o, f):
        if isinstance(o, YggdrasilExtendedSerializable):
            o.deserialize(f)
        else:
            f.set_fields(o)

    def must_sync_deserialization(self):
        return False

    def can_be_instantiated(self):
        return True


class Serializer(YggdrasilSerializer):
    pass
