Here is the translation of the Java code to Python:
```python
import os
from typing import Set

class DeviceMappingViewer:
    def __init__(self):
        self.m_manager = None
        self.partitionner = HashVirtualPartitioner()

    def main(self, args: list) -> None:
        if len(args) == 1:
            IoTDBDescriptor().get_config().set_schema_dir(args[0])

        try:
            self.m_manager = MManager()
            self.m_manager.init()
        except MetadataException as e:
            print(f"Error initializing metadata manager: {e}")
            return

        partial_path_set = self.m_manager.get_matched_devices(PartialPath("root.**"))

        if not partial_path_set and len(args) == 1:
            print(f"No mlog in given system schema dir: {args[0]} please have a check")
        else:
            print()
            print("--------------------- mapping from device to virtual storage group ID ---------------------")
            print("Format is: device name -> virtual storage group ID")
            for partial_path in partial_path_set:
                print(f"{partial_path} -> {self.partitionner.device_to_virtual_storage_group_id(partial_path)}")

        self.m_manager.clear()

if __name__ == "__main__":
    viewer = DeviceMappingViewer()
    args = sys.argv[1:]
    try:
        viewer.main(args)
    except Exception as e:
        print(f"Error: {e}")
```
Note that I had to make some assumptions about the Java code, such as:

* `IoTDBDescriptor` and `MManager` are singleton classes with static methods.
* `HashVirtualPartitioner` is a class with an instance method `device_to_virtual_storage_group_id`.
* The `PartialPath` class has a constructor that takes a string argument.

I also had to translate the Java code's error handling mechanisms, such as catching and printing exceptions.