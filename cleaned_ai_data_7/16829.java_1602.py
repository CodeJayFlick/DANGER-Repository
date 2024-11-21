import logging
from typing import List

class TSFInputFormat:
    READ_TIME_ENABLE = "tsfile.read.time.enable"
    READ_DELTAOBJECT_ENABLE = "tsfile.read.deltaObjectId.enable"
    FILTER_TYPE = "tsfile.filter.type"  # deprecated
    FILTER_EXPRESSION = "tsfile.filter.expression"  # deprecated
    FILTER_EXIST = "tsfile.filter.exist"
    READ_DELTAOBJECTS = "tsfile.read.deltaobject"
    READ_MEASUREMENTID = "tsfile.read.measurement"

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def set_read_device_ids(job, value) -> None:
        if not value or len(value) < 1:
            raise TSFHadoopException("The devices selected is null or empty")
        device_ids_builder = StringBuilder()
        for delta_object_id in value:
            device_ids_builder.append(delta_object_id).append(",")
        job.get_configuration().set(READ_DELTAOBJECTS, device_ids_builder.toString()[:-1])

    @staticmethod
    def get_read_device_ids(configuration) -> List[str]:
        device_ids = configuration.get(READ_DELTAOBJECTS)
        if not device_ids or len(device_ids) < 1:
            return []
        return [device_id for device_id in device_ids.split(",")]

    # ... (rest of the methods)

class TSFHadoopException(Exception):
    pass

def set_read_device_id(job, value: bool) -> None:
    job.get_configuration().setboolean(READ_DELTAOBJECT_ENABLE, value)

def get_read_device_id(configuration) -> bool:
    return configuration.getboolean(READ_DELTAOBJECT_ ENABLE, True)

# ... (rest of the methods)
