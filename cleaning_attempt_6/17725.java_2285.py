import logging
from typing import Dict, List, Tuple

class LogReplayer:
    def __init__(self,
                log_node_prefix: str,
                insert_file_path: str,
                modification_file: object,
                current_ts_file_resource: object,
                mem_table: object,
                sequence: bool) -> None:
        self.log_node_prefix = log_node_prefix
        self.insert_file_path = insert_file_path
        self.modification_file = modification_file
        self.current_ts_file_resource = current_ts_file_resource
        self.mem_table = mem_table
        self.sequence = sequence

    def replay_logs(self, supplier: callable) -> None:
        log_node = MultiFileLogNodeManager().get_instance() \
            .get_node(f"{self.log_node_prefix}{FSFactoryProducer.get_fs_factory().get_file(self.insert_file_path).name}", supplier)
        
        log_reader = log_node.get_log_reader()
        try:
            while log_reader.has_next():
                plan = log_reader.next()
                if isinstance(plan, InsertPlan):
                    self.replay_insert(plan)
                elif isinstance(plan, DeletePlan):
                    self.replay_delete(plan)
        except PathNotExistException as e:
            # can not get path because it is deleted
            pass
        except Exception as e:
            logging.warn(f"recover wal of {self.insert_file_path} failed", exc_info=e)

        log_reader.close()
        try:
            self.modification_file.close()
        except IOException as e:
            logging.error("Cannot close the modifications file {}", self.modification_file.get_file_path(), exc_info=e)

    def replay_delete(self, delete_plan: DeletePlan) -> None:
        for path in delete_plan.get_paths():
            for device in IoTDB.meta_manager().get_belonged_devices(path):
                self.mem_table.delete(
                    path,
                    device,
                    delete_plan.get_delete_start_time(),
                    delete_plan.get_delete_end_time()
                )
                
                self.modification_file.write(
                    Deletion(
                        path,
                        current_ts_file_resource.get_ts_file_size(),
                        delete_plan.get_delete_start_time(),
                        delete_plan.get_delete_end_time()
                    )
                )

    def replay_insert(self, insert_plan: InsertPlan) -> None:
        if self.current_ts_file_resource is not None:
            min_time = max_time = 0
            if isinstance(insert_plan, InsertRowPlan):
                min_time = ((InsertRowPlan)insert_plan).get_time()
                max_time = ((InsertRowPlan)insert_plan).get_time()
            else:
                min_time = ((InsertTabletPlan)insert_plan).get_min_time()
                max_time = ((InsertTabletPlan)insert_plan).get_max_time()

            device_id = insert_plan.get_prefix_path().get_device_path().get_full_path() if not insert_plan.is_aligned() else insert_plan.get_prefix_path().get_full_path()
            
            last_end_time = self.current_ts_file_resource.get_end_time(device_id)
            if last_end_time != float('-inf') and last_end_time >= min_time and self.sequence:
                return

            start_time = temp_start_time_map.get(device_id) or min_time
            end_time = temp_end_time_map.get(device_id) or max_time
            
            temp_start_time_map[device_id] = start_time
            temp_end_time_map[device_id] = end_time

        measurement_mnodes = IoTDB.meta_manager().get_measurement_mnodes(insert_plan.get_prefix_path(), insert_plan.get_measurements())

        if isinstance(insert_plan, InsertRowPlan):
            self.mem_table.insert((InsertRowPlan)insert_plan)
        else:
            self.mem_table.insert_tablet(
                (InsertTabletPlan)insert_plan,
                0,
                ((InsertTabletPlan)insert_plan).get_row_count()
            )

    def check_data_type_and_mark_failed(self, mnodes: List[object], tplan: InsertPlan) -> None:
        for i in range(len(mnodes)):
            if mnodes[i] is None:
                tplan.mark_failed_measurement_insertion(
                    i,
                    PathNotExistException(tplan.get_prefix_path().get_full_path() + IoTDBConstant.PATH_SEPARATOR + tplan.get_measurements()[i])
                )
            elif not tplan.is_aligned() and mnodes[i].schema.type != tplan.data_types[i]:
                tplan.mark_failed_measurement_insertion(
                    i,
                    DataTypeMismatchException(mnodes[i].name, tplan.data_types[i], mnodes[i].schema.type)
                )
            elif tplan.is_aligned() and mnodes[i].schema.get_sub_measurements_ts_data_type_list()[i] != tplan.data_types[i]:
                tplan.mark_failed_measurement_insertion(
                    i,
                    DataTypeMismatchException(mnodes[i].name + "." + mnodes[i].schema.get_sub_measurements_list()[i], tplan.data_types[i], mnodes[i].schema.get_sub_measurements_ts_data_type_list()[i])
                )

    temp_start_time_map: Dict[str, int] = {}
    temp_end_time_map: Dict[str, int] = {}

# Usage
log_replayer = LogReplayer(
    log_node_prefix="prefix",
    insert_file_path="/path/to/file.tsfile",
    modification_file=modification_file,
    current_ts_file_resource=current_ts_file_resource,
    mem_table=mem_table,
    sequence=True
)

supplier = lambda: supplier_array  # replace with your own supplier

log_replayer.replay_logs(supplier)
