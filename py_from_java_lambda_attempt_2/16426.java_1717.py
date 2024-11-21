Here is the translation of the Java code into Python:

```Python
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
```

```Python
class ClusterDescriptor:
    _logger = logging.getLogger(__name__)
    instance = None

    def __init__(self):
        if not isinstance(ClusterDescriptor.instance, type(self)):
            ClusterDescriptor.instance = self
            self.config = ClusterConfig()
            self.load_props()

    @classmethod
    def get_instance(cls) -> 'ClusterDescriptor':
        return cls.instance

    def load_props(self) -> None:
        url = self.get_prop_url()
        if url is not None:
            try:
                with open(url, 'r') as file:
                    properties = Properties.load(file)
                    for key, value in properties.items():
                        setattr(self.config, key, value)
            except Exception as e:
                _logger.warn(f"Fail to find config file {url} because {e}")

    def get_prop_url(self) -> str:
        url = System.getProperty('iotdb_conf', None)
        if url is None:
            return None
        else:
            return f"{url}/{ClusterConfig.CONFIG_NAME}"

    # ... other methods ...
```

```Python
class Properties(dict):
    @classmethod
    def load(cls, file: 'File') -> dict:
        result = {}
        for line in file.readlines():
            key_value_pair = line.strip().split('=')
            if len(key_value_pair) == 2:
                key, value = key_value_pair
                try:
                    result[key] = int(value)
                except ValueError:
                    pass
        return result

    @classmethod
    def get(cls, file: 'File') -> dict:
        result = {}
        for line in file.readlines():
            key_value_pair = line.strip().split('=')
            if len(key_value_pair) == 2:
                key, value = key_value_pair
                try:
                    result[key] = int(value)
                except ValueError:
                    pass
        return result

    @classmethod
    def get_int(cls, file: 'File', key: str) -> int:
        for line in file.readlines():
            pair = line.strip().split('=')
            if len(pair) == 2 and pair[0] == key:
                try:
                    return int(pair[1])
                except ValueError:
                    pass
        raise Exception(f"Key {key} not found")

    @classmethod
    def get_bool(cls, file: 'File', key: str) -> bool:
        for line in file.readlines():
            pair = line.strip().split('=')
            if len(pair) == 2 and pair[0] == key:
                return pair[1].lower() == "true"
        raise Exception(f"Key {key} not found")

    @classmethod
    def get_long(cls, file: 'File', key: str) -> int:
        for line in file.readlines():
            pair = line.strip().split('=')
            if len(pair) == 2 and pair[0] == key:
                try:
                    return long(pair[1])
                except ValueError:
                    pass
        raise Exception(f"Key {key} not found")

    @classmethod
    def get_string(cls, file: 'File', key: str) -> str:
        for line in file.readlines():
            pair = line.strip().split('=')
            if len(pair) == 2 and pair[0] == key:
                return pair[1]
        raise Exception(f"Key {key} not found")
```

```Python
def hostname_to_ip(hostname: str) -> str:
    try:
        address = InetAddress.get_by_name(hostname)
        return address.host_address
    except UnknownHostException as e:
        _logger.error(f"Failed to resolve host name {hostname}: {e}")
        raise

class QueryProcessException(Exception):
    pass
```

```Python
def get_seed_url_list(seed_urls: str) -> List[str]:
    if seed_urls is None or len(seed_urls.strip()) == 0:
        return []
    
    url_list = []
    for node_url in seed_urls.split(','):
        node_url = node_url.strip()
        if node_url != "":
            url_list.append(node_url)
    
    return url_list
```

```Python
def load_hot_modified_props(self, properties: dict) -> None:
    self.config.max_concurrent_client_num = int(properties.get('max_concurrent_ client_num', str(self.config.max_concurrent_client_num)))
    self.config.connection_timeout_in_ms = int(properties.get('connection_timeout_ms', str(self.config.connection_timeout_in_ms)))

    _logger.info(f"Set cluster configuration {properties}")
```

```Python
def load_props(self) -> None:
    url = self.get_prop_url()
    if url is not None:
        try:
            with open(url, 'r') as file:
                properties = Properties.load(file)
                for key, value in properties.items():
                    setattr(self.config, key, value)
        except Exception as e:
            _logger.warn(f"Fail to find config file {url} because {e}")
```

```Python
def replace_hostname_with_ip(self) -> None:
    if not self.config.get_internal_ip().startswith('['):
        try:
            internal_ip = hostname_to_ip(self.config.get_internal_ip())
            self.config.set_internal_ip(internal_ip)
        except UnknownHostException as e:
            _logger.error(f"Failed to resolve host name {self.config.get_internal_ip()}: {e}")

    seed_urls = []
    for seed_url in self.config.get_seed_node_urls():
        if not seed_url.startswith('['):
            try:
                hostname = InetAddresses.is_inetAddress(seed_url)
                new_seed_ip = hostname_to_ip(hostname)
                seed_urls.append(new_seed_ip + ':' + seed_url.split(':')[1])
            except UnknownHostException as e:
                _logger.error(f"Failed to resolve host name {seed_url}: {e}")
        else:
            seed_urls.append(seed_url)

    self.config.set_seed_node_urls(seed_urls)
```

```Python
def get_prop_url(self) -> str:
    url = System.getProperty('iotdb_conf', None)
    if url is None:
        return None

    return f"{url}/{ClusterConfig.CONFIG_NAME}"
```

Please note that Python does not have direct equivalent of Java's `Properties` class. The above code uses a dictionary to simulate the behavior of the `Properties` class in Java.