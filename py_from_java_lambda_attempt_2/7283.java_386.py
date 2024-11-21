Here is the equivalent Python code:

```Python
class Ext4DxTail:
    def __init__(self, provider):
        self.dt_reserved = None
        self.dt_checksum = None
        
        if isinstance(provider, bytes):
            reader = BinaryReader(provider)
        else:
            raise ValueError("Invalid provider type")
        
        try:
            self.dt_reserved = int.from_bytes(reader.read(4), 'little')
            self.dt_checksum = int.from_bytes(reader.read(4), 'little')
        except Exception as e:
            print(f"Error: {e}")

    @property
    def dt_reserved(self):
        return self.dt_reserved

    @dt_reserved.setter
    def dt_reserved(self, value):
        self.dt_reserved = value

    @property
    def dt_checksum(self):
        return self.dt_checksum

    @dt_checksum.setter
    def dt_checksum(self, value):
        self.dt_checksum = value

class BinaryReader:
    def __init__(self, provider):
        if isinstance(provider, bytes):
            self.provider = provider
        else:
            raise ValueError("Invalid provider type")

    def read(self, size):
        return self.provider[:size]

def main():
    # Example usage
    ext4dx_tail = Ext4DxTail(b'\x00\x01\x02\x03\x04\x05\x06\x07')
    print(ext4dx_tail.dt_reserved)
    print(ext4dx_tail.dt_checksum)

if __name__ == "__main__":
    main()
```

Please note that Python does not have direct equivalent of Java's `StructConverter` and `BinaryReader`. The above code is a simple translation to Python.