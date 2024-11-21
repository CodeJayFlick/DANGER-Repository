Here is the translation of the Java code to Python:

```Python
importndefrecord = None


class Nfc:
    @staticmethod
    def create_mime(mime_type: str, payload: bytes) -> ndefrecord:
        mime_bytes = mime_type.encode('ascii')
        return ndefrecord(NdefRecord.TNF_MIME_MEDIA, mime_bytes, b'', payload)

    @staticmethod
    def extract_mime_payload(mime_type: str, message: 'NdefMessage') -> bytes | None:
        mime_bytes = mime_type.encode('ascii')

        for record in message.get_records():
            if record.get_tnf() == NdefRecord.TNF_MIME_MEDIA and record.get_type().tobytes() == mime_bytes:
                return record.get_payload()

        return None


class ndefrecord:
    def __init__(self, tnf: int, type_: bytes, id_: bytes, payload: bytes):
        self.tnf = tnf
        self.type_ = type_
        self.id_ = id_
        self.payload = payload

    @property
    def get_tnf(self) -> int:
        return self.tnf


class NdefMessage(list):
    def __init__(self, *args):
        super().__init__(*args)

    def get_records(self) -> list:
        return self[:]
```

Please note that Python does not have direct equivalent of Java's `@Nullable` annotation.