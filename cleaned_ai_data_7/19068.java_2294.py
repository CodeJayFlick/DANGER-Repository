import unittest
from google.protobuf import message as protobuf_message
from typing import List, Tuple

class TestSerialization:
    def __init__(self):
        self.params = [
            {
                'generator': lambda: create_entry(),
                'type': CommitLogEntry,
                'serializer': lambda x: to_proto(x).SerializeToString(),
                'deserializer': lambda x: proto_to_commit_log_entry(protobuf_message.parse_string(x))
            },
            {
                'generator': lambda: create_global_state(),
                'type': GlobalStatePointer,
                'serializer': lambda x: x.SerializeToString(),
                'deserializer': lambda x: protobuf_message.parse_string(x)
            }
        ]

    def test_entries(self):
        for param in self.params:
            value = param['generator']()
            serialized = param['serializer'](value)
            print(f"{param['type'].__name__} serialized size: {len(serialized)}")

            deserialized = param['deserializer'](serialized)
            assert value == deserialized

    def test_serialize1k(self):
        for param in self.params:
            value = param['generator']()
            for _ in range(1000):
                serialized = param['serializer'](value)
                deserialized = param['deserializer'](serialized)
                assert value == deserialized
                reserialized = param['serializer'](deserialized)
                assert serialized == reserialized

    def test_deserialize1k(self):
        for param in self.params:
            value = param['generator']()
            for _ in range(1000):
                serialized = param['serializer'](value)
                deserialized = param['deserializer'](serialized)
                assert value == deserialized
                reserialized = param['serializer'](deserialized)
                assert serialized == reserialized

    def test_type_serialization(self, param: Tuple[Callable[[Any], Any], Type[Any]]):
        for _ in range(500):
            entry = param[0]()
            proto = to_proto(entry).SerializeToString()
            deserialized = protobuf_message.parse_string(proto)

            print(f"{param[1].__name__} serialized size: {len(proto)}")

            assert proto == str(deserialized)
            reserialized = to_proto(deserialized).SerializeToString()
            assert proto == reserialized

    def create_entry(self):
        return CommitLogEntry(
            created_time=System.nanoTime() / 1000,
            hash=random_hash(),
            parents=[random_bytes(32) for _ in range(20)],
            puts=[
                AdapterTypes.ContentsIdWithBytes(
                    contents_id=AdapterTypes.ContentsId(id=random_string(64)),
                    type=2,
                    value=random_bytes(120)
                ) for _ in range(20)
            ]
        )

    def create_global_state(self):
        return GlobalStatePointer(
            global_id=random_bytes(32),
            put_named_references={
                random_string(32): RefPointer(type=RefPointer.Type.Branch, hash=random_bytes(32))
                for _ in range(50)
            }
        )

def to_proto(x: Any) -> protobuf_message.Message:
    # implementation of this function is not provided
    pass

def proto_to_commit_log_entry(proto: str) -> CommitLogEntry:
    # implementation of this function is not provided
    pass

class RefPointer:
    def __init__(self, type: int, hash: bytes):
        self.type = type
        self.hash = hash

if __name__ == '__main__':
    unittest.main()
