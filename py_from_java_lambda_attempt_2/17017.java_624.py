Here is the translation of the Java code into Python:

```Python
import logging
from typing import List, Dict

class ReadOnlyMemChunk:
    def __init__(self,
                 measurement_uid: str,
                 data_type: int,
                 encoding: int,
                 tv_list: 'TVList',
                 props: Dict[str, str],
                 size: int,
                 deletion_list: List['TimeRange']) -> None:
        self.measurement_uid = measurement_uid
        self.data_type = data_type
        self.encoding = encoding

        if props is not None and props.get('MAX_POINT_NUMBER') is not None:
            try:
                float_precision = int(props['MAX_POINT_NUMBER'])
            except ValueError as e:
                logging.warn(f"The format of MAX_POINT_NUMBER {props['MAX_POINT_NUMBER']} is not correct. Using default float precision.")
        else:
            float_precision = 0

        if float_precision < 0:
            logging.warn("The MAX_POINT_NUMBER shouldn't be less than 0. Using default float precision {}.".format(TSFileDescriptor.getInstance().getConfig().getFloatPrecision()))
            float_precision = TSFileDescriptor.getInstance().getConfig().getFloatPrecision()

        self.chunk_data = tv_list
        self.chunk_data_size = size
        self.deletion_list = deletion_list

        self.chunk_point_reader = tv_list.get_iterator(float_precision, encoding, chunk_data_size, deletion_list)
        self.init_chunk_meta()

    def init_chunk_meta(self) -> None:
        stats_by_type = Statistics().get_stats_by_type(self.data_type)

        if not self.is_empty():
            iterator = self.chunk_data.get_iterator(float_precision, encoding, chunk_data_size, self.deletion_list)
            while iterator.has_next_time_value_pair():
                time_value_pair = iterator.next_time_value_pair()
                match self.data_type:
                    case 0:  # BOOLEAN
                        stats_by_type.update(time_value_pair.timestamp, time_value_pair.value.get_boolean())
                    case 1:  # TEXT
                        stats_by_type.update(time_value_pair.timestamp, time_value_pair.value.get_binary())
                    case 2:  # FLOAT
                        stats_by_type.update(time_value_pair.timestamp, time_value_pair.value.get_float())
                    case 3:  # INT32
                        stats_by_type.update(time_value_pair.timestamp, time_value_pair.value.get_int())
                    case 4:  # INT64
                        stats_by_type.update(time_value_pair.timestamp, time_value_pair.value.get_long())
                    case 5:  # DOUBLE
                        stats_by_type.update(time_value_pair.timestamp, time_value_pair.value.get_double())

        stats_by_type.set_empty(self.is_empty())
        self.cached_meta_data = ChunkMetadata(self.measurement_uid, self.data_type, 0, stats_by_type)
        self.cached_meta_data.set_chunk_loader(MemChunkLoader(self))
        self.cached_meta_data.set_version(long.max_value)

    def __init_vector_chunk_meta__(self,
                                     schema: 'IMeasurementSchema',
                                     tv_list: 'TVList',
                                     size: int,
                                     deletion_list: List['TimeRange']) -> None:
        time_statistics = Statistics().get_stats_by_type(TSDataType.VECTOR)
        value_statistics = [Statistics().get_stats_by_type(schema.get_sub_measurements_ts_data_type(i)) for i in range(len(schema.get_sub_measurements_ts_data_type()))]
        chunk_metadata_list = []

        if not self.is_empty():
            iterator = tv_list.get_iterator(float_precision, encoding, chunk_data_size, deletion_list)
            while iterator.has_next_time_value_pair():
                time_value_pair = iterator.next_time_value_pair()
                match schema.get_sub_measurements_ts_data_type(0):
                    case 0:  # BOOLEAN
                        value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_boolean())
                    case 1:  # TEXT
                        value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_binary())
                    case 2:  # FLOAT
                        value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_float())
                    case 3:  # INT32
                        value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_int())
                    case 4:  # INT64
                        value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_long())
                    case 5:  # DOUBLE
                        value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_double())

        for statistic in value_statistics:
            statistic.set_empty(self.is_empty())

        vector_chunk_metadata = VectorChunkMetadata(ChunkMetadata(self.measurement_uid, TSDataType.VECTOR, 0, time_statistics), chunk_metadata_list)
        vector_chunk_metadata.set_chunk_loader(MemChunkLoader(self))
        vector_chunk_metadata.set_version(long.max_value)

    def update_value_statistics_for_single_column__(self,
                                                     schema: 'IMeasurementSchema',
                                                     value_statistics: List[Statistics],
                                                     time_value_pair: TimeValuePair) -> None:
        match schema.get_sub_measurements_ts_data_type(0):
            case 0:  # BOOLEAN
                value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_boolean())
            case 1:  # TEXT
                value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_binary())
            case 2:  # FLOAT
                value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_float())
            case 3:  # INT32
                value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_int())
            case 4:  # INT64
                value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_long())
            case 5:  # DOUBLE
                value_statistics[0].update(time_value_pair.timestamp, time_value_pair.value.get_double())

    def update_value_statistics__(self,
                                    schema: 'IMeasurementSchema',
                                    value_statistics: List[Statistics],
                                    time_value_pair: TimeValuePair) -> None:
        for i in range(len(schema.get_sub_measurements_ts_data_type())):
            if time_value_pair.value.get_vector()[i] is not None:
                match schema.get_sub_measurements_ts_data_type(i):
                    case 0:  # BOOLEAN
                        value_statistics[i].update(time_value_pair.timestamp, time_value_pair.value.get_vector()[i].get_boolean())
                    case 1:  # TEXT
                        value_statistics[i].update(time_value_pair.timestamp, time_value_pair.value.get_vector()[i].get_binary())
                    case 2:  # FLOAT
                        value_statistics[i].update(time_value_pair.timestamp, time_value_pair.value.get_vector()[i].get_float())
                    case 3:  # INT32
                        value_statistics[i].update(time_value_pair.timestamp, time_value_pair.value.get_vector()[i].get_int())
                    case 4:  # INT64
                        value_statistics[i].update(time_value_pair.timestamp, time_value_pair.value.get_vector()[i].get_long())
                    case 5:  # DOUBLE
                        value_statistics[i].update(time_value_pair.timestamp, time_value_pair.value.get_vector()[i].get_double())

    def get_data_type__(self) -> int:
        return self.data_type

    def is_empty__(self) -> bool:
        return not self.chunk_point_reader.has_next_time_value_pair()

    def get_chunk_meta_data__(self) -> 'IChunkMetadata':
        return self.cached_meta_data

    def get_point_reader__(self) -> 'IPointReader':
        self.chunk_point_reader = self.chunk_data.get_iterator(float_precision, encoding, chunk_data_size, self.deletion_list)
        return self.chunk_point_reader

    def get_measurement_uid__(self) -> str:
        return self.measurement_uid
```

Note that this is a direct translation of the Java code into Python. The resulting Python code may not be idiomatic or efficient for Python.