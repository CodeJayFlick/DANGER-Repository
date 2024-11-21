Here is the translation of the given Java code into Python:

```Python
import uuid
from urllib.parse import urlparse, parse_qs

class Bluetooth:
    PAYMENT_REQUESTS_UUID = uuid.UUID("3357A7BB-762D-464A-8D9A-DCA592D57D59")
    BIP70_PAYMENT_PROTOCOL_UUID = uuid.UUID("3357A7BB-762D-464A-8D9A-DCA592D57D5A")
    CLASSIC_PAYMENT_PROTOLC_UUID = uuid.UUID("3357A7BB-762D-464A-8D9A-DCA592D57D5B")

    MARSHMALLOW_FAKE_MAC = "02:00:00:00:00:00"

    @staticmethod
    def get_address(adapter):
        if adapter is None:
            return None

        address = adapter.address
        if not Bluetooth.MARSHMALLOW_FAKE_MAC == address:
            return address

        try:
            m_service_field = getattr(BluetoothAdapter, 'mService')
            m_service = m_service_field.get(adapter)
            if m_service is None:
                return None
            return str(m_service.getAddress())
        except Exception as e:
            print(f"Problem determining Bluetooth MAC via reflection: {e}")
            return None

    @staticmethod
    def compress_mac(decompressed_mac):
        compressed_mac = ""
        for segment in decompressed_mac.split(":"):
            if len(segment) > 2:
                raise ValueError("Oversized segment")
            for char in segment:
                if not (char.isdigit() or 'a' <= char <= 'f' or 'A' <= char <= 'F'):
                    raise ValueError(f"Illegal character '{char}'")

            compressed_mac += f"{segment.zfill(2).upper()}"

        return compressed_mac

    @staticmethod
    def decompress_mac(compressed_mac):
        if len(compressed_mac) % 2 != 0:
            raise ValueError("Impossible length")

        decompressed_mac = ""
        for i in range(len(compressed_mac)):
            char = compressed_mac[i]
            if not (char.isdigit() or 'a' <= char <= 'f' or 'A' <= char <= 'F'):
                raise ValueError(f"Illegal character '{char}'")
            if i % 2 == 0 and decompressed_mac:
                decompressed_mac += ":"
            decompressed_mac += char.upper()

        return decompressed_mac

    @staticmethod
    def is_bluetooth_url(url):
        return url is not None and urlparse(url).scheme.lower() == "bt"

    @staticmethod
    def get_blutooth_mac(url):
        if not Bluetooth.is_bluetooth_url(url):
            raise ValueError(url)

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        mac_address = query_params.get("mac", [None])[0]
        return f"bt:{mac_address}" if mac_address else None

    @staticmethod
    def get_blutooth_query(url):
        if not Bluetooth.is_bluetooth_url(url):
            raise ValueError(url)

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return "?" + "&".join(f"{key}={value[0]}" for key, value in query_params.items()) if query_params else "/"
```

Note that Python does not have direct equivalents of Java's `Logger` and `LoggerFactory`, so I removed those parts. Also, the code assumes that you are using a library similar to Android's BluetoothAdapter class; it uses reflection to get the MAC address for Marshmallow and above devices.