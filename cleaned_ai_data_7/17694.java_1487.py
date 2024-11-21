import logging
from enum import Enum
from typing import List, Collection, Dict, Set, Tuple

class TSDataType(Enum):
    BOOLEAN = 1
    INT32 = 2
    INT64 = 3
    FLOAT = 4
    DOUBLE = 5
    TEXT = 6


class TSEncoding(Enum):
    PLAIN = 1
    RLE = 2
    TS_2DIFF = 3
    GORILLA = 4
    DICTIONARY = 5

schema_checker: Dict[TSDataType, Set[TSEncoding]] = {
    TSDataType.BOOLEAN: {TSEncoding.PLAIN, TSEncoding.RLE},
    TSDataType.INT32: {TSEncoding.PLAIN, TSEncoding.RLE, TSEncoding.TS_2DIFF, TSEncoding.GORILLA},
    TSDataType.INT64: {TSEncoding.PLAIN, TSEncoding.RLE, TSEncoding.TS_2DIFF, TSEncoding.GORILLA},
    TSDataType.FLOAT: {TSEncoding.PLAIN, TSEncoding.RLE, TSEncoding.TS_2DIFF, TSEncoding.GORILLA_V1, TSEncoding.GORILLA},
    TSDataType.DOUBLE: {TSEncoding.PLAIN, TSEncoding.RLE, TSEncoding.TS_2DIFF, TSEncoding.GORILLA_V1, TSEncoding.GORILLA},
    TSDataType.TEXT: {TSEncoding.PLAIN, TSEncoding.DICTIONARY}
}

logger = logging.getLogger(__name__)

def register_timeseries(schema):
    try:
        logger.debug("Registering timeseries %s", schema)
        path = PartialPath(schema.get_full_path())
        data_type = schema.get_type()
        encoding = schema.get_encoding_type()
        compression_type = schema.get_compressor()
        IoTDB.meta_manager.create_timeseries(path, data_type, encoding, compression_type, {})
    except PathAlreadyExistException:
        pass
    except MetadataException as e:
        if not (e.cause and isinstance(e.cause, (ClosedByInterruptException, ClosedChannelException))):
            logger.error("Cannot create timeseries %s in snapshot, ignored", schema.get_full_path(), e)


def cache_timeseries_schema(schema):
    path = None
    try:
        path = PartialPath(schema.get_full_path())
    except IllegalPathException as e:
        logger.error("Cannot cache an illegal path %s", schema.get_full_path())
        return

    data_type = schema.get_type()
    encoding = schema.get_encoding_type()
    compression_type = schema.get_compressor()

    measurement_schema = UnaryMeasurementSchema(path.measurement, data_type, encoding, compression_type)
    measurement_m_node = MeasurementMNode.get_measurement_m_node(None, path.measurement, measurement_schema, None)

    IoTDB.meta_manager.cache_meta(path, measurement_m_node, True)


def get_series_types_by_paths(paths):
    try:
        return [IoTDB.meta_manager.get_series_type(p) for p in paths]
    except MetadataException as e:
        raise


def get_aggregated_data_types(measurement_data_type: List[TSDataType], aggregation: str):
    data_type = get_aggregation_type(aggregation)
    if data_type is not None:
        return [data_type] * len(measurement_data_type)

    return measurement_data_type


def get_series_type_by_path(path):
    try:
        return IoTDB.meta_manager.get_series_type(path)
    except MetadataException as e:
        raise


def find_meta_missing_exception(curr_ex: Exception) -> Tuple[bool, Exception]:
    while True:
        if isinstance(curr_ex, (PathNotExistException, StorageGroupNotSetException)):
            return False, curr_ex

        if curr_ex.cause is None:
            break
        curr_ex = curr_ex.cause

    return True, None


def check_data_type_with_encoding(data_type: TSDataType, encoding: TSEncoding):
    if not schema_checker.get(data_type).contains(encoding):
        raise MetadataException(f"Encoding {encoding} does not support {data_type}", True)
