Here is the translation of the given Java code into equivalent Python:

```Python
import json
from google.protobuf import ByteString as PBByteString
from google.protobuf import InvalidProtocolBufferException as ProtoBufInvalidException
from typing import Optional

class TableCommitMetaStoreWorker:
    def __init__(self):
        self.meta_serializer = MetadataSerializer()

    @staticmethod
    def to_store_on_reference_state(contents: 'Contents') -> PBByteString:
        if isinstance(contents, IcebergTable):
            state_builder = ObjectTypes.IcebergMetadataPointer()
            state_builder.set_metadata_location(contents.get_metadata_location())
            return contents.to_byte_string(state_builder.build())

        elif isinstance(contents, DeltaLakeTable):
            table_builder = ObjectTypes.DeltaLakeTable()
            for metadata_location in contents.get_metadata_location_history():
                table_builder.add_all_metadata_locations(metadata_location)
            for checkpoint_location in contents.get_checkpoint_location_history():
                table_builder.add_all_checkpoint_locations(checkpoint_location)
            if contents.get_last_checkpoint() is not None:
                table_builder.set_last_checkpoint(contents.get_last_checkpoint())
            return contents.to_byte_string(table_builder.build())

        elif isinstance(contents, SqlView):
            view = contents
            builder = ObjectTypes.SqlView()
            builder.set_dialect(view.get_dialect().name)
            builder.set_sql_text(view.get_sql_text())
            return contents.to_byte_string(builder.build())

        else:
            raise ValueError("Unknown type " + str(type(contents)))

    @staticmethod
    def to_store_global_state(contents: 'Contents') -> PBByteString:
        if isinstance(contents, IcebergTable):
            state_builder = ObjectTypes.IcebergGlobal()
            state_builder.set_id_generators(contents.get_id_generators())
            return contents.to_byte_string(state_builder.build())

        else:
            raise ValueError("Unknown type " + str(type(contents)))

    @staticmethod
    def value_from_store(on_reference_value: PBByteString, global_state: Optional[PBByteString]) -> 'Contents':
        if on_reference_value is None or not isinstance(on_reference_value, PBByteString):
            return IcebergTable()

        contents = parse(on_reference_value)
        if global_state:
            try:
                global_contents = ObjectTypes.Contents.parse_from(global_state.get_bytes())
            except ProtoBufInvalidException as e:
                raise ValueError("Failure parsing data", str(e))
        else:
            global_contents = None

        switcher = {
            0: lambda: ImmutableDeltaLakeTable.builder().id(contents.id).build(),
            1: lambda: IcebergTable.of(contents.get_metadata_location(), contents.get_id_generators()),
            2: lambda: ImmutableSqlView.builder().dialect(Dialect.valueOf(contents.sql_view.dialect)).sql_text(contents.sql_view.sql_text).id(contents.id).build()
        }

        return switcher[contents.type](if global_contents else None)

    @staticmethod
    def parse(on_reference_value: PBByteString) -> 'Contents':
        try:
            return ObjectTypes.Contents.parse_from(on_reference_value)
        except ProtoBufInvalidException as e:
            raise ValueError("Failure parsing data", str(e))

    def get_metadata_serializer(self):
        return self.meta_serializer

class MetadataSerializer:
    def to_bytes(self, value: CommitMeta) -> PBByteString:
        try:
            return PBByteString.copy_from(json.dumps(value).encode())
        except Exception as e:
            raise ValueError("Couldn't serialize commit meta " + str(value), str(e))

    def from_bytes(self, bytes: PBByteString) -> CommitMeta:
        try:
            return json.loads(bytes.decode()) if bytes else ImmutableCommitMeta.builder().message("unknown").committer("unknown").hash("unknown").build()
        except Exception as e:
            raise ValueError(str(e))
```

Please note that this is a direct translation of the given Java code into equivalent Python. It might not be perfect, and some adjustments may be necessary to make it work correctly in your specific use case.