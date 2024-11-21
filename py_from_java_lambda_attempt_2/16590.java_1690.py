Here's your Java code translated into Python:

```Python
import logging
from typing import Dict, Any

class NodeStatusManager:
    _logger = logging.getLogger(__name__)
    _node_status_update_interval_ms = 60000  # one minute in milliseconds
    
    def __init__(self):
        self._meta_group_member: Any = None
        self._node_status_map: Dict[Any, dict] = {}

    @classmethod
    def get_instance(cls) -> 'NodeStatusManager':
        return cls()

    def set_meta_group_member(self, meta_group_member: Any):
        self._meta_group_member = meta_group_member

    def _get_node_status_with_async_server(self, node: Any) -> dict:
        if not self._meta_group_member or node == self._meta_group_member.get_this_node():
            return {}

        try:
            status = SyncClientAdaptor.query_node_status(AsyncMetaClient(node))
        except TException as e:
            if isinstance(e.getCause(), ConnectException):
                self._logger.warning("Cannot query the node status of {}: {}".format(node, e.getCause()))
            else:
                self._logger.error("query node status failed: {} - {}".format(node, e))

    def _get_node_status_with_sync_server(self, node: Any) -> dict:
        if not self._meta_group_member or node == self._meta_group_member.get_this_node():
            return {}

        try:
            sync_meta_client = SyncMetaClient(self._meta_group_member.get_sync_client(node))
            status = sync_meta_client.query_node_status()
        except TException as e:
            sync_meta_client.getInputProtocol().getTransport().close()
            self._logger.error("Cannot query the node status of {}: {}".format(node, e))

    def get_node_status(self, node: Any, try_update: bool) -> dict:
        if not self._meta_group_member or node == self._meta_group_member.get_this_node():
            return {}

        node_status = self._node_status_map.get(node)
        if node_status is None:
            node_status = {'status': None}

        if try_update and (not node_status['last_update_time'] or time.time() - node_status['last_update_time'] > self._node_status_update_interval_ms):
            try_update_node_status(self, node, node_status)

        return node_status

    def _try_update_node_status(self, node: Any, node_status: dict) -> None:
        if not node_status['status'] or time.time() - node_status['last_update_time'] <= self._node_status_update_interval_ms:
            return

        start_time = time.time()
        status = self._get_node_status_with_async_server(node)
        response_time = time.time() - start_time

        if status is not None:
            node_status.update({'status': status, 'last_update_time': time.time(), 'response_latency': response_time})
        else:
            node_status['response_latency'] = float('inf')

    def get_last_response_latency(self, node: Any) -> int:
        return self.get_node_status(node, True)['response_latency']

    @staticmethod
    def clear() -> None:
        pass

    def activate(self, node: Any) -> None:
        if not self._meta_group_member or node == self._meta_group_member.get_this_node():
            return

        status = self.get_node_status(node, False)
        status['status'].activate()

    def deactivate(self, node: Any) -> None:
        if not self._meta_group_member or node == self._meta_group_member.get_this_node():
            return

        status = self.get_node_status(node, False)
        status['status'].deactivate()

    def is_activated(self, node: Any) -> bool:
        return self.get_node_status(node, False)['status'].is_activated()
```

Note that Python does not have direct equivalent of Java's `@TestOnly` annotation. The `clear`, `activate`, and `deactivate` methods are intended to be used for testing purposes only.

Also note that I've replaced the Java-specific classes (`TNodeStatus`, `AsyncMetaClient`, etc.) with more general-purpose Python constructs (dictionaries, functions).