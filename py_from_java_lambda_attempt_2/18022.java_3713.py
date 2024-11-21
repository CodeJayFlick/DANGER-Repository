Here is the translation of the Java code to Python:

```Python
import os
from typing import List

class UnseqTsFileRecoverTest:
    def __init__(self):
        self.ts_f = None
        self.writer = None
        self.node = None
        self.schema = None
        self.resource = None
        self.version_controller = VersionController()

    @classmethod
    def setup(cls) -> None:
        os.makedirs("testNode/0", exist_ok=True)
        ts_f = open("1-1-1.tsfile", "wb")
        cls.ts_f = ts_f

        schema = Schema()
        for i in range(10):
            for j in range(10):
                path = f"root.sg.device{i}.sensor{j}"
                measurement_schema = UnaryMeasurementSchema(f"sensor{j}", TSDataType.INT64, TSEncoding.PLAIN)
                schema.register_timeseries(path, measurement_schema)

        writer = TsFileWriter(ts_f, schema)
        ts_record = TSRecord(100, "root.sg.device99")
        ts_record.add_tuple(DataPoint.get_data_point(TSDataType.INT64, "sensor4", str(0)))
        writer.write(ts_record)
        ts_record = TSRecord(2, "root.sg.device99")
        ts_record.add_tuple(DataPoint.get_data_point(TSDataType.INT64, "sensor1", str(0)))
        writer.write(ts_record)

        for i in range(10):
            for j in range(10):
                ts_record = TSRecord(i, f"root.sg.device{j}")
                for k in range(10):
                    ts_record.add_tuple(DataPoint.get_data_point(TSDataType.INT64, f"sensor{k}", str(k)))
                writer.write(ts_record)

        writer.flush_all_chunk_groups()
        writer.iowriter.close()

    @classmethod
    def tearDown(cls) -> None:
        os.remove("1-1-1.tsfile")
        cls.resource.close()
        MmapUtil.clean((cls.node.delete()[0]))

class VersionController:
    def __init__(self):
        self.i = 0

    def next_version(self) -> int:
        return self.i + 1

    def curr_version(self) -> int:
        return self.i


def test() -> None:
    performer = TsFileRecoverPerformer("testNode/0", resource, False, False)
    performer.recover(True, lambda: [ByteBuffer.allocateDirect(IoTDBDescriptor.getInstance().getConfig().getWalBufferSize() // 2), ByteBuffer.allocateDirect(IoTDBDescriptor.getInstance().getConfig().getWalBufferSize() // 2)], lambda x: [x[0].clean((MappedByteBuffer)(x[1])), x[1].clean((MappedByteBuffer)(x[0]))])
    performer.close()

    assert resource.get_start_time("root.sg.device99") == 1
    assert resource.get_end_time("root.sg.device99") == 300
    for i in range(10):
        assert resource.get_start_time(f"root.sg.device{i}") == 0
        assert resource.get_end_time(f"root.sg.device{i}") == 9

    file_reader = TsFileSequenceReader(ts_f.name, True)
    metadata_querier = MetadataQuerierByFileImpl(file_reader)
    chunk_loader = CachedChunkLoaderImpl(file_reader)

    path = Path("root.sg.device1", "sensor1")

    un_seq_merge_reader = PriorityMergeReader()
    priority_value = 1
    for chunk_metadata in metadata_querier.get_chunk_meta_data_list(path):
        chunk = chunk_loader.load_chunk(chunk_metadata)
        chunk_reader = ChunkReader(chunk, None)
        un_seq_merge_reader.add_reader(ChunkDataIterator(chunk_reader), priority_value++)
    for i in range(10):
        timeValuePair = un_seq_merge_reader.current_time_value_pair()
        assert timeValuePair.get_timestamp() == i
        assert (timeValuePair.get_value().get_value()) == 11
        un_seq_merge_reader.next_time_value_pair()

    un_seq_merge_reader.close()
    file_reader.close()


if __name__ == "__main__":
    UnseqTsFileRecoverTest.setup()
    test()
```

Please note that this is a direct translation of the Java code to Python, and it may not be optimal or idiomatic in terms of Python coding style.