Here is the translation of the Java code to Python:

```Python
import base64
from PIL import Image
import io
import zlib

class Qr:
    QR_CODE_WRITER = 'pyzbar.pyzbar'

    def bitmap(self, content):
        try:
            result = self.QR_CODE_WRITER.encode(content)
            width, height = result.size()
            pixels = [0] * (width * height)

            for y in range(height):
                offset = y * width
                for x in range(width):
                    if result.get(x, y) is not None:
                        pixels[offset + x] = -1

            bitmap = Image.new('L', (width, height))
            stream = io.BytesIO()
            bitmap.putalpha(stream.write(pixels))

        except Exception as e:
            print(f"problem creating qr code: {e}")
            return None
        else:
            return bitmap

    def encode_compress_binary(self, bytes):
        try:
            bos = io.BytesIO(len(bytes))
            gos = zlib.compressobj()
            gos.compress(bytes)
            gos.flush()

            gzipped_bytes = bos.getvalue()
            use_compression = len(gzipped_bytes) < len(bytes)

            str = f"{use_compression and 'Z' or '-'}{base64.b32encode(use_compression and gzipped_bytes or bytes).decode('utf-8')}"

        except Exception as e:
            raise RuntimeError(e)
        else:
            return str

    def encode_binary(self, bytes):
        return base64.b32encode(bytes).decode('utf-8')

    def decode_decompress_binary(self, content):
        try:
            use_compression = content[0] == 'Z'
            bytes = base64.b32decode(content[1:])

            is = io.BytesIO()
            if use_compression:
                gos = zlib.decompressobj(wbits=15)
                while True:
                    chunk = is.read(4096)
                    if not chunk:
                        break
                    gos.append(chunk)
                bytes = bytearray(gos.partial_flush(), 'utf-8')
            else:
                bytes = base64.b32decode(content[1:])

        except Exception as e:
            raise IOError(e)

    def decode_binary(self, content):
        return base64.b32decode(content).decode('utf-8')

if __name__ == "__main__":
    qr = Qr()
    print(qr.encode_compress_binary(b"Hello World"))
```

Please note that the QR code generation part is not implemented in Python as it requires a library like `pyzbar` which I have used here.