Here is the translation of the Java code into Python:

```Python
import os
from decimal import DecimalFormat

class SyncUtils:
    IP_SEPARATOR = "\\."

    def __init__(self):
        pass

    @staticmethod
    def get_snapshot_file(file_path: str) -> str:
        relative_file_path = (
            file_path.rsplit(os.sep, 4)[0] + os.sep +
            file_path.rsplit(os.sep, 3)[1] + os.sep +
            file_path.rsplit(os.sep, 2)[1] + os.sep +
            file_path.rsplit(os.sep, 1)[1]
        )
        snapshot_dir = SyncSenderDescriptor().get_config()["snapshotPath"]
        if not os.path.exists(snapshot_dir):
            os.makedirs(snapshot_dir)
        return os.path.join(snapshot_dir, relative_file_path)

    @staticmethod
    def is_empty(sending_file_list: dict) -> bool:
        for key, value in sending_file_list.items():
            for k2, v2 in value.items():
                for k3, v3 in v2.items():
                    if not set(v3):
                        return False
        return True

    @staticmethod
    def verify_ip_segment(ip_white_list: str, ip_address: str) -> bool:
        ip_segments = [x.strip() for x in ip_white_list.split(",")]
        for segment in ip_segments:
            subnet_mask = int(segment.split("/")[1])
            segment = "/".join([segment.split("/")[0], ""])
            if SyncUtils.verify_ip(segment, ip_address, subnet_mask):
                return True
        return False

    @staticmethod
    def verify_ip(ip_segment: str, ip_address: str, subnet_mark: int) -> bool:
        ip_segment_binary = ""
        for segment in ip_segment.split("\\."):
            binary_segment = format(int(int(segment)), "08b")
            ip_segment_binary += binary_segment[:subnet_mark]
        ip_segments = [x.strip() for x in ip_address.split("\\.")]
        ip_address_binary = ""
        for segment in ip_segments:
            binary_segment = format(int(int(segment)), "08b")
            ip_address_binary += binary_segment[:subnet_mark]
        return ip_address_binary == ip_segment_binary

class SyncSenderDescriptor:
    @staticmethod
    def get_config() -> dict:
        pass  # This method should be implemented based on the actual configuration mechanism used in your application.

# Example usage:

sync_utils = SyncUtils()
file_path = "path/to/file"
snapshot_file_path = sync_utils.get_snapshot_file(file_path)
print(snapshot_file_path)

sending_file_list = {"key1": {"k2": {"v3": ["file1", "file2"]}}}
is_empty_result = sync_utils.is_empty(sending_file_list)
print(is_empty_result)

ip_white_list = "192.168.0.0/24, 10.0.0.0/8"
ip_address = "192.168.0.100"
verify_ip_segment_result = sync_utils.verify_ip_segment(ip_white_list, ip_address)
print(verify_ip_segment_result)

segment = "192.168.0."
address = "192.168.0.100"
subnet_mark = 16
verify_ip_result = sync_utils.verify_ip(segment, address, subnet_mark)
print(verify_ip_result)
```

Please note that the `SyncSenderDescriptor` class is not implemented in this translation as it seems to be a part of your application's configuration mechanism and should be replaced with actual implementation based on how you manage configurations in your Python code.