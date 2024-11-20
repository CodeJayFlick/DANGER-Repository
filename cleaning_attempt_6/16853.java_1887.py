class IoTDInfluxDBFactory:
    def __init__(self):
        pass

IoTDBInfluxDBFactory = IoTDInfluxDBFactory()

def connect(url: str, username: str, password: str) -> 'InfluxDB':
    if not url or not username:
        raise ValueError("url and username cannot be empty")
    return IoTDBInfluxDB(url, username, password)

def connect(host: str, rpc_port: int, username: str, password: str) -> 'InfluxDB':
    if not host or not username:
        raise ValueError("host and username cannot be empty")
    return IoTDBInfluxDB(host, rpc_port, username, password)

class InfluxDB:
    def __init__(self, url: str):
        pass

def connect(url: str, username: str, password: str) -> 'InfluxDB':
    if not url or not username:
        raise ValueError("url and username cannot be empty")
    return IoTDBInfluxDB(url, username, password)

class OkHttpClient:
    def __init__(self):
        pass

def connect(url: str, username: str, password: str) -> 'InfluxDB':
    if not url or not username:
        raise ValueError("url and username cannot be empty")
    return IoTDBInfluxDB(url, username, password)

class Session:
    def __init__(self):
        pass

def connect(builder: 'Session.Builder') -> 'InfluxDB':
    return IoTDBInfluxDB(builder)
