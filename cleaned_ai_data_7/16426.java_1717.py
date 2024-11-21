import logging
from typing import List

class ClusterConfig:
    def __init__(self):
        self.internal_ip = None
        self.internal_meta_port = 0
        self.internal_data_port = 0
        # ... other variables ...

    def set_internal_ip(self, internal_ip: str) -> None:
        self.internal_ip = internal_ip

    def get_internal_ip(self) -> str:
        return self.internal_ip

    # ... getter and setter methods for other variables ...
