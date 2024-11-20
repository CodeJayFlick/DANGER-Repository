Here is the translation of the Java code into Python:

```Python
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any

class MultiFileLogNodeManager:
    def __init__(self):
        self.node_map: Dict[str, 'WriteLogNode'] = {}
        self.executor_service: Any = None
        self.config = IoTDBConfig()

    @property
    def logger(self) -> logging.Logger:
        return logging.getLogger(__name__)

    def force_task(self):
        if not self.config.is_read_only():
            for node in list(self.node_map.values()):
                try:
                    node.force_sync()
                except Exception as e:
                    self.logger.error(f"Cannot force {node}, because {e}")
        else:
            if self.first_read_only:
                self.logger.warning("system mode is read-only, the force flush WAL task is stopped")
                self.first_read_only = False
            return

    def get_instance(self) -> 'MultiFileLogNodeManager':
        return MultiFileLogNodeManager()

    def get_node(self, identifier: str, supplier: callable) -> 'WriteLogNode':
        node = self.node_map.get(identifier)
        if node is None:
            node = WriteLogNode(identifier)
            old_node = self.node_map.put_if_absent(identifier, node)
            if old_node is not None:
                return old_node
            else:
                node.init_buffer(supplier())
        return node

    def delete_node(self, identifier: str) -> None:
        try:
            node = self.node_map.pop(identifier)
            if node is not None:
                consumer(node.delete())
        except Exception as e:
            raise IOException(f"failed to close {node}, because {e}")

    def close(self):
        for node in list(self.node_map.values()):
            try:
                node.close()
            except Exception as e:
                self.logger.error(f"failed to close {node}, because {e}")
        self.node_map.clear()

    def start(self) -> None:
        if not self.config.is_enable_wal():
            return
        if self.config.get_force_wal_period_in_ms() > 0:
            self.executor_service = ThreadPoolExecutor()
            self.executor_service.submit(self.force_task, *self.config.get_force_wal_period_in_ms())

    def stop(self) -> None:
        if not self.config.is_enable_wal():
            return
        if self.executor_service is not None:
            self.executor_service.shutdown()
            try:
                self.executor_service.wait_done(30)
            except Exception as e:
                self.logger.warning("force flush wal thread still doesn't exit after 30s")
                Thread.current_thread().interrupt()

    def get_id(self) -> Any:
        return ServiceType.WAL_SERVICE

class InstanceHolder:
    instance: 'MultiFileLogNodeManager' = MultiFileLogNodeManager()
```

Note that Python does not have direct equivalent of Java's `Map` and `ScheduledExecutorService`. Instead, we use a dictionary (`node_map`) to store the nodes. For scheduling tasks, we can use Python's built-in threading library or third-party libraries like `concurrent.futures`.