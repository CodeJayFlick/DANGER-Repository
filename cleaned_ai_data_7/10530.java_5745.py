import io

class ObjectStorageStreamAdapter:
    def __init__(self, out=None):
        self.out = out
        if not isinstance(out, (io.BytesIO, io.StringIO)):
            raise TypeError("out must be an instance of BytesIO or StringIO")

    def put_int(self, value: int) -> None:
        try:
            self.out.write(int.to_bytes(value, 4, 'big'))
        except Exception as e:
            print(f"Error writing integer {value}: {e}")

    def get_int(self) -> int:
        try:
            return int.from_bytes(self.out.read(4), 'big')
        except Exception as e:
            print(f"Error reading integer: {e}")
            return 0

    def put_byte(self, value: bytes) -> None:
        try:
            self.out.write(value)
        except Exception as e:
            print(f"Error writing byte array {value}: {e}")

    def get_byte(self) -> bytes:
        try:
            return self.out.read()
        except Exception as e:
            print(f"Error reading byte: {e}")
            return b''

    # ... similar methods for put_short, get_short, etc.
