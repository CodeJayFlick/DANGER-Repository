import logging
from collections import deque, defaultdict

class AsyncClientPool:
    def __init__(self, async_client_factory):
        self.async_client_factory = async_client_factory
        self.wait_client_timeout_ms = ClusterDescriptor().get_config().get_wait_client_timeout_ms()
        self.max_connection_per_node = \
            ClusterDescriptor().get_config().get_max_client_per_node_per_member()

    def get_client(self, node: 'Node', activated_only=True) -> 'AsyncClient':
        cluster_node = ClusterNode(node)
        if not NodeStatusManager.get_instance().is_activated(node):
            return None

        client_stack = self.client_caches[cluster_node]
        if not client_stack:
            intialize_client_cache(cluster_node)

        with lock(client_stack):
            if client_stack.empty():
                node_client_num = self.node_client_nums[cluster_node]
                if node_client_num >= self.max_connection_per_node:
                    return wait_for_client(client_stack, cluster_node)
                else:
                    async_client = self.async_client_factory.get_async_client(cluster_node, self)
                    self.node_client_nums[cluster_node] += 1
            elif client_stack.pop():
                pass

        return client_stack[-1]

    def put_client(self, node: 'Node', client: 'AsyncClient'):
        cluster_node = ClusterNode(node)

        if isinstance(client, AsyncDataClient):
            call = client.get_curr_method()
        elif isinstance(client, AsyncMetaClient):
            call = client.get_curr_method()

        with lock(client_stack):
            client_stack.push(client)
            client_stack.notify_all()

    def on_error(self, node: 'Node'):
        cluster_node = ClusterNode(node)

        if not self.client_caches[cluster_node]:
            return

        with lock(client_stack):
            while not client_stack.empty():
                client = client_stack.pop()
                if isinstance(client, AsyncDataClient):
                    client.close()
                elif isinstance(client, AsyncMetaClient):
                    client.close()

    def on_complete(self, node: 'Node'):
        NodeStatusManager.get_instance().activate(node)

    @staticmethod
    def recreate_client(node: 'Node', async_client_factory):
        cluster_node = ClusterNode(node)
        if not self.client_caches[cluster_node]:
            return

        with lock(client_stack):
            try:
                client = async_client_factory.get_async_client(cluster_node, self)
                client_stack.push(client)
            except IOException as e:
                logging.error(f"Cannot create a new client for {node}", e)

    @staticmethod
    def get_node_client_num_map():
        return node_client_nums

class ClusterNode:
    def __init__(self, node: 'Node'):
        self.node = node

class AsyncClientPoolFactory:
    pass

# Initialize the map and deque
client_caches = defaultdict(deque)
node_client_nums = {}

def lock(obj):
    # Python does not have built-in support for locks like Java. You can use threading.Lock() or queue.Queue()
    return obj  # For simplicity, just return the object itself.

class AsyncDataClient:
    def get_curr_method(self):
        pass

class AsyncMetaClient:
    def get_curr_method(self):
        pass
