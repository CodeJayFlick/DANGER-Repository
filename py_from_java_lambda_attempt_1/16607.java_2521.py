Here is the equivalent Python code:

```Python
class ClusterNode:
    def __init__(self):
        pass

    def __init__(self, internal_ip, meta_port, node_identifier, data_port, client_port, client_ip):
        self.internal_ip = internal_ip
        self.meta_port = meta_port
        self.node_identifier = node_identifier
        self.data_port = data_port
        self.client_port = client_port
        self.client_ip = client_ip

    def __eq__(self, other):
        if not isinstance(other, ClusterNode):
            return False
        return (self.internal_ip == other.internal_ip and 
                self.meta_port == other.meta_port and 
                self.data_port == other.data_port and 
                self.client_port == other.client_port and 
                self.client_ip == other.client_ip)

    def __hash__(self):
        return hash((self.internal_ip, self.meta_port, self.data_port, self.client_port, self.client_ip))

    def __str__(self):
        return f"ClusterNode{{'internal_ip': '{self.internal_ip}', 'meta_port': {self.meta_port}, " \
               f"'node_identifier': {self.node_identifier}, 'data_port': {self.data_port}, " \
               f"'client_port': {self.client_port}, 'client_ip': '{self.client_ip}'}}"
```

Note that Python does not have a direct equivalent to Java's `@Override` annotation. However, it is good practice in Python to include docstrings and use the built-in methods like `__init__`, `__eq__`, etc., as shown above.