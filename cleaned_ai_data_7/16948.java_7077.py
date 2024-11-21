import logging
from typing import List, Set, Dict, Any

class TimeseriesMetadata:
    def __init__(self):
        pass  # TO DO: implement this class in Python


class TimeSeriesMetadataCacheKey:
    def __init__(self, file_path: str, device: str, measurement_id: str) -> None:
        self.file_path = file_path
        self.device = device
        self.measurement_id = measurement_id

    @property
    def full_key(self):
        return f"{self.device}.{self.measurement_id}"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, TimeSeriesMetadataCacheKey):
            return False
        return (self.file_path == other.file_path and 
                self.device == other.device and 
                self.measurement_id == other.measurement_id)

    def __hash__(self) -> int:
        return hash((self.file_path, self.device, self.measurement_id))


class TimeSeriesMetadataCache:
    _logger = logging.getLogger(__name__)

    def __init__(self):
        if not hasattr(self, 'instance'):
            self.instance = Caffeine.new_builder().maximumWeight(1024 * 1024).weigher(
                lambda key: RamUsageEstimator.shallow_size_of(key) + 
                           RamUsageEstimator.size_of(key.device) + 
                           RamUsageEstimator.size_of(key.measurement_id)
            ).record_stats().build()
        self.entry_average_size = AtomicLong(0)

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = TimeSeriesMetadataCache()
        return cls.instance

    def get(self, key: TimeSeriesMetadataCacheKey, all_sensors: Set[str], debug=False) -> TimeseriesMetadata:
        if not self.is_cache_enabled():
            ts_file_sequence_reader = FileReaderManager.get_instance().get(key.file_path, True)
            bloom_filter = ts_file_sequence_reader.read_bloom_filter()
            if bloom_filter and not bloom_filter.contains(f"{key.device}.{key.measurement_id}"):
                return None
            timeseries_metadata = ts_file_sequence_reader.read_timeseries_metadata(Path(key.device, key.measurement_id), False)
        else:
            timeseries_metadata = self.instance.get_if_present(key)

        if timeseries_metadata is None:
            if debug:
                self._logger.info(f"Cache miss: {key.full_key} in file: {key.file_path}")
                self._logger.info("Device: {}, all sensors: {}".format(key.device, all_sensors))
            # allow for the parallelism of different devices
            with self.devices.compute_if_absent(lambda k: WeakReference(k)):
                timeseries_metadata = self.get(key, all_sensors)
        if timeseries_metadata is None:
            return None

        return TimeseriesMetadata(timeseries_metadata)

    def get_vector_timeseries_metadata_list_from_cache(self, key: TimeSeriesMetadataCacheKey, sub_sensor_list: List[str], res: List[TimeseriesMetadata]) -> None:
        timeseries_metadata = self.instance.get_if_present(key)
        if timeseries_metadata is not None:
            res.append(timeseries_metadata)
            for sub_sensor in sub_sensor_list:
                timeseries_metadata = self.instance.get_if_present(TimeSeriesMetadataCacheKey(key.file_path, key.device, sub_sensor))
                if timeseries_metadata is not None:
                    res.append(timeseries_metadata)

    def read_timeseries_metadata_for_vector(self, ts_file_sequence_reader: Any, key: TimeSeriesMetadataCacheKey, sub_sensor_list: List[str], all_sensors: Set[str]) -> List[TimeseriesMetadata]:
        path = Path(key.device, key.measurement_id)
        time_series_metadata_list = ts_file_sequence_reader.read_timeseries_metadata(path, all_sensors)

    def calculate_time_series_metadata_hit_ratio(self) -> float:
        return self.instance.stats().hit_rate()

    def get_eviction_count(self) -> int:
        return self.instance.stats().eviction_count()

    def get_max_memory(self) -> int:
        return 1024 * 1024

    def get_average_load_penalty(self) -> float:
        return self.instance.stats().average_load_penalty()

    def get_average_size(self) -> int:
        return self.entry_average_size.get()

    @property
    def devices(self):
        if not hasattr(self, '_devices'):
            self._devices = WeakHashMap()
        return self._devices

    def clear(self) -> None:
        self.instance.invalidate_all()
        self.instance.clean_up()

    def remove(self, key: TimeSeriesMetadataCacheKey) -> None:
        self.instance.invalidate(key)

    @property
    def is_cache_enabled(self):
        if not hasattr(self, '_is_cache_enabled'):
            self._is_cache_enabled = True  # TO DO: implement this property in Python


# singleton pattern
class TimeSeriesMetadataCacheHolder:
    instance = TimeSeriesMetadataCache()
