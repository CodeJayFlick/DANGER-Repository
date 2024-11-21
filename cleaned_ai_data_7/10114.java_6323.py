import io
import zipfile
from struct import pack, unpack

class ItemSerializer:
    MAGIC_NUMBER = 0x2e30212634e92c20L
    FORMAT_VERSION = 1
    ZIP_ENTRY_NAME = "FOLDER_ITEM"
    IO_BUFFER_SIZE = 32 * 1024

    def __init__(self):
        pass

    @staticmethod
    def output_item(item_name, content_type, file_type, length, content_file, packed_file_path, monitor=None) -> None:
        with open(packed_file_path, 'wb') as out_file:
            try:
                # Output header containing: original item name and content type
                obj_out = io.BytesIO()
                obj_out.write(pack('>L', ItemSerializer.MAGIC_NUMBER))
                obj_out.write(pack('>I', ItemSerializer.FORMAT_VERSION))
                obj_out.write(item_name.encode('utf-8'))
                if content_type:
                    obj_out.write(content_type.encode('utf-8'))
                else:
                    obj_out.write(b'')
                obj_out.write(pack('>I', file_type))
                obj_out.write(pack('>Q', length))

                # Output item content
                zip_out = zipfile.ZipFile(out_file, 'w', compression=zipfile.ZIP_DEFLATED)
                entry = zipfile.ZipInfo(ItemSerializer.ZIP_ENTRY_NAME)
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.size = int(length)

                with open(content_file.name, 'rb') as content:
                    item_out = io.BytesIO()
                    if monitor is not None:
                        monitored_stream = io.BytesIO()
                        for chunk in iter(lambda: content.read(1024), b''):
                            item_out.write(chunk)
                            monitored_stream.write(chunk)
                            monitor.update(int(length) - len(monitored_stream.getvalue()))
                    else:
                        while True:
                            chunk = content.read(IO_BUFFER_SIZE)
                            if not chunk:
                                break
                            item_out.write(chunk)

                zip_out.writestr(entry, item_out.getvalue())
            except Exception as e:
                out_file.close()
                packed_file_path.unlink()

    @staticmethod
    def is_packed_file(file_path) -> bool:
        try:
            with open(file_path, 'rb') as file:
                magic_bytes = file.read(8)
                if len(magic_bytes) < 8 or not pack('>Q', *unpack('>QQ', magic_bytes)) == ItemSerializer.MAGIC_NUMBER:
                    return False
                return True
        except Exception as e:
            return False

    @staticmethod
    def is_packed_file_stream(stream) -> bool:
        stream.seek(6)
        magic_bytes = stream.read(8)
        if len(magic_bytes) < 8 or not pack('>Q', *unpack('>QQ', magic_bytes)) == ItemSerializer.MAGIC_NUMBER:
            return False
        return True

# Example usage:

serializer = ItemSerializer()
monitor = None  # Replace with your own monitor implementation, e.g., tqdm.tqdm()

content_file_path = 'path_to_your_content_file'
packed_file_path = 'path_to_your_packed_file'

try:
    serializer.output_item('your_item_name', 'your_content_type', 1, 1024 * 1024, content_file_path, packed_file_path, monitor)
except Exception as e:
    print(f"An error occurred: {e}")

packed_file_is_valid = ItemSerializer.is_packed_file(packed_file_path)

print(f"Packed file is valid: {packed_file_is_valid}")
