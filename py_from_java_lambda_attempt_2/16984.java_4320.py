Here is the translation of the Java code to Python:
```
import iotdb_config  # assuming this module contains IoTDBDescriptor class

class InnerSpaceCompactionTaskFactory:
    def create_task(self,
                    logical_storage_group_name: str,
                    virtual_storage_group: str,
                    time_partition: int,
                    ts_file_manager: object,
                    ts_file_resource_list: list,
                    selected_ts_file_resources: list,
                    sequence: bool) -> object:
        config = iotdb_config.IoTDBDescriptor.getInstance().get_config()
        compaction_strategy = config.get_inner_compaction_strategy()
        return compaction_strategy.get_compaction_task(
            logical_storage_group_name, virtual_storage_group, time_partition,
            ts_file_manager, ts_file_resource_list, selected_ts_file_resources, sequence
        )
```
Note that I assumed the existence of an `iotdb_config` module containing the `IoTDBDescriptor` class. You will need to create this module and define the classes and methods within it in order for this code to work.

Also, Python does not have a direct equivalent to Java's package declaration at the top of the file. Instead, you would typically put your imports and definitions into separate files or modules, depending on your project structure and organization.