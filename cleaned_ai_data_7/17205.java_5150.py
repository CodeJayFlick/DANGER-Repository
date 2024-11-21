import collections

class PayloadFormatManager:
    _map = collections.defaultdict(dict)

    @classmethod
    def init(cls):
        from importlib_metadata import metadata
        for ep in metadata.entry_points():
            if ep.name.startswith('org.apache.iotdb.db.mqtt.PayloadFormatter'):
                cls._map[ep.name] = ep.load()

    @classmethod
    def get_payload_format(cls, name: str) -> 'PayloadFormat':
        Preconditions.check_argument(name in cls._map, f"Unknown payload format named: {name}")
        return cls._map[name]

# This is not a real Python class, but rather a placeholder for the PayloadFormatter interface/class
class PayloadFormat:
    pass

if __name__ == '__main__':
    PayloadFormatManager.init()
