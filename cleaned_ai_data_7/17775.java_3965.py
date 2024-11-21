import os
from typing import Set, List, Dict, Tuple

class CompactionFileGeneratorUtils:
    @staticmethod
    def get_target_ts_file_resource_from_source_resource(source_resource: 'TsFileResource') -> 'TsFileResource':
        ts_file_name = TsFileNameGenerator.get_ts_file_name(source_resource.ts_file.name)
        return TsFileResource(os.path.join(TestConstant.BASE_OUTPUT_PATH, 
                                            str(ts_file_name.time) + IoTDBConstant.FILE_NAME_SEPARATOR + 
                                            str(ts_file_name.version) + IoTDBConstant.FILE_NAME_SEPARATOR + 
                                            str(ts_file_name.inner_compaction_cnt + 1) + IoTDBConstant.FILE_NAME_SEPARATOR + 
                                            str(ts_file_name.cross_compaction_cnt) + ".tsfile"))

    @staticmethod
    def generate_ts_file_resource(sequence: bool, index: int) -> 'TsFileResource':
        if sequence:
            return TsFileResource(os.path.join(TestConstant.BASE_OUTPUT_PATH, 
                                                str(index) + IoTDBConstant.FILE_NAME_SEPARATOR + 
                                                str(index) + IoTDBConstant.FILE_NAME_SEPARATOR + 
                                                "0" + IoTDBConstant.FILE_NAME_SEPARATOR + 
                                                "0" + ".tsfile"))
        else:
            return TsFileResource(os.path.join(TestConstant.BASE_OUTPUT_PATH, 
                                               str(index + 10000) + IoTDBConstant.FILE_NAME_SEPARATOR + 
                                               str(index + 10000) + IoTDBConstant.FILE_NAME_SEPARATOR + 
                                               "0" + IoTDBConstant.FILE_NAME_SEPARATOR + 
                                               "0" + ".tsfile"))

    @staticmethod
    def write_ts_file(full_paths: Set[str], chunk_page_points_num: List[List[long]], start_time: long, new_ts_file_resource: 'TsFileResource') -> None:
        # disable auto page seal and seal page manually
        prev_max_number_of_points_in_page = TSFileDescriptor.getInstance().getConfig().getMaxNumberOfPointsInPage()
        TSFileDescriptor.getInstance().getConfig().setMaxNumberOfPointsInPage(int.MAX_VALUE)

        writer = RestorableTsFileIOWriter(new_ts_file_resource.ts_file)
        device_measurement_map = {}
        for full_path in full_paths:
            partial_path = PartialPath(full_path)
            sensors = device_measurement_map.setdefault(partial_path.device, [])
            sensors.append(partial_path.measurement)

        for (device, sensors) in device_measurement_map.items():
            writer.start_chunk_group(device)
            for sensor in sensors:
                curr_time = start_time
                chunk_writer = ChunkWriterImpl(UnaryMeasurementSchema(sensor, TSDataType.INT64), True)
                for page_points_num in chunk_page_points_num:
                    for points in page_points_num:
                        for _ in range(points):
                            chunk_writer.write(curr_time, curr_time, False)
                            new_ts_file_resource.update_start_time(device, curr_time)
                            new_ts_file_resource.update_end_time(device, curr_time)
                            curr_time += 1
                    chunk_writer.seal_current_page()
                chunk_writer.write_to_file_writer(writer)

            writer.end_chunk_group()

        new_ts_file_resource.serialize()
        writer.end_file()
        new_ts_file_resource.close()

        TSFileDescriptor.getInstance().getConfig().setMaxNumberOfPointsInPage(prev_max_number_of_points_in_page)

    @staticmethod
    def write_chunk_to_ts_file_with_time_range(full_paths: Set[str], chunk_page_points_num: List[List[long]], new_ts_file_resource: 'TsFileResource') -> None:
        # disable auto page seal and seal page manually
        prev_max_number_of_points_in_page = TSFileDescriptor.getInstance().getConfig().getMaxNumberOfPointsInPage()
        TSFileDescriptor.getInstance().getConfig().setMaxNumberOfPointsInPage(int.MAX_VALUE)

        writer = RestorableTsFileIOWriter(new_ts_file_resource.ts_file)
        device_measurement_map = {}
        for full_path in full_paths:
            partial_path = PartialPath(full_path)
            sensors = device_measurement_map.setdefault(partial_path.device, [])
            sensors.append(partial_path.measurement)

        curr_chunks_index = 0
        for (device, sensors) in device_measurement_map.items():
            writer.start_chunk_group(device)
            for sensor in sensors:
                chunks = chunk_page_points_num[curr_chunks_index]
                chunk_writer = ChunkWriterImpl(UnaryMeasurementSchema(sensor, TSDataType.INT64), True)
                for pages in chunks:
                    for start_end_time in pages:
                        for _ in range(start_end_time[1] - start_end_time[0]):
                            chunk_writer.write(_, _, False)
                            new_ts_file_resource.update_start_time(device, _)
                            new_ts_file_resource.update_end_time(device, _)

                    chunk_writer.seal_current_page()
                chunk_writer.write_to_file_writer(writer)
                curr_chunks_index += 1

            writer.end_chunk_group()

        new_ts_file_resource.serialize()
        writer.end_file()
        new_ts_file_resource.close()

        TSFileDescriptor.getInstance().getConfig().setMaxNumberOfPointsInPage(prev_max_number_of_points_in_page)

    @staticmethod
    def generate_mods(to_delete_timeseries_and_time: Dict[str, Tuple[long, long]], target_ts_file_resource: 'TsFileResource', is_compaction_mods: bool) -> None:
        modification_file = ModificationFile.get_compaction_mods(target_ts_file_resource) if is_compaction_mods else ModificationFile.get_normal_mods(target_ts_file_resource)
        for full_path, start_end_time in to_delete_timeseries_and_time.items():
            deletion = Deletion(PartialPath(full_path), long.MAX_VALUE, *start_end_time)
            modification_file.write(deletion)

        modification_file.close()
