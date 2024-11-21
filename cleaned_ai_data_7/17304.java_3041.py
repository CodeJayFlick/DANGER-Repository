class SetSchemaTemplatePlan:
    def __init__(self):
        self.template_name = None
        self.prefix_path = None

    def set_template_name(self, template_name: str) -> None:
        self.template_name = template_name

    def get_template_name(self) -> str:
        return self.template_name

    def set_prefix_path(self, prefix_path: str) -> None:
        self.prefix_path = prefix_path

    def get_prefix_path(self) -> str:
        return self.prefix_path


class PhysicalPlan:
    def __init__(self):
        pass

    @staticmethod
    def serialize_to_buffer(buffer, template_name, prefix_path, index):
        buffer.write((PhysicalPlanType.SET_SCHEMA_TEMPLATE.value).to_bytes(1, 'big'))
        ReadWriteIOUtils.write_string(buffer, template_name)
        ReadWriteIOUtils.write_string(buffer, prefix_path)
        buffer.write(index.to_bytes(8, 'big'))

    @staticmethod
    def deserialize_from_buffer(buffer):
        template_name = ReadWriteIOUtils.read_string(buffer)
        prefix_path = ReadWriteIOUtils.read_string(buffer)
        index = int.from_bytes(buffer.read(8), 'big')
        return SetSchemaTemplatePlan(template_name, prefix_path)

class DataOutputStream:
    @staticmethod
    def write_byte(stream, value):
        stream.write(value.to_bytes(1, 'big'))

    @staticmethod
    def read_long(stream):
        return int.from_bytes(stream.read(8), 'big')

# Helper functions for serialization and deserialization

def serialize_to_stream(stream, template_name: str, prefix_path: str) -> None:
    PhysicalPlan.serialize_to_buffer(buffer=stream,
                                      buffer_size=len(template_name)+len(prefix_path),
                                      index=None)

def deserialize_from_stream(stream):
    return PhysicalPlan.deserialize_from_buffer(buffer=stream)
