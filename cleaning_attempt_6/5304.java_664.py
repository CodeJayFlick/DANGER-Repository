import os
from typing import List

class AbstractLoaderExporter:
    def __init__(self, name: str, help_location: dict):
        self.name = name
        self.help_location = help_location

    def supports_file_format(self, file_format: str) -> bool:
        # Implement your logic here to check if the given file format is supported by this exporter.
        pass  # Replace with actual implementation.

    def export(self, file_path: str, domain_obj: dict, address_set_view: dict, task_monitor=None):
        try:
            if not isinstance(domain_obj.get('program'), dict):  # Check if program type matches
                print(f"Unsupported type: {domain_obj['program']['class']}")
                return False

            program = domain_obj.get('program')
            memory = program.get('memory')

            file_format = program.get('executable_format')
            if not self.supports_file_format(file_format):
                print(f"Unsupported file format: {file_format}")
                return False

            # Write source program's file bytes to a temp file
            temp_file_path = os.path.join(os.getcwd(), 'ghidra_export_' + str(int(os.urandom(16).hex()))[:8] + '.temp')
            with open(temp_file_path, 'wb') as f:
                for fb in memory.get('all_file_bytes'):
                    if program['executable_path'].endswith(fb['filename']):
                        FileUtilities.copy_stream_to_stream(FileBytesInputStream(fb), f, task_monitor)

            # Undo relocations in the temp file
            error = None
            with open(temp_file_path, 'r+b') as f:
                for reloc in program.get('relocation_table').get('relocations'):
                    address_source_info = memory.get('address_source_info')(reloc['address'])
                    if address_source_info is not None and address_source_info.get('file_offset') >= 0:
                        offset = address_source_info.get('file_offset')
                        bytes = reloc['bytes']
                        f.seek(offset)
                        f.write(bytes)

            # If errors occurred, log them and delete the malformed temp file
            if error is not None:
                print(error)
                try:
                    os.remove(temp_file_path)
                except Exception as e:
                    print(f"Failed to delete malformed file: {temp_file_path}")
                return False

            # Move temp file to desired output file
            from_path = Path(temp_file_path)
            to_path = Path(file_path)
            if not os.replace(from_path, to_path):
                print(f"Failed to move file: {file_path}")

        except Exception as e:
            print(str(e))

    def get_options(self) -> List[dict]:
        return []

    def set_options(self, options: List[dict]):
        pass

class FileBytesInputStream:
    def __init__(self, file_bytes):
        self.file_bytes = file_bytes
        self.size = file_bytes.get('size')
        self.pos = 0

    def read(self) -> int:
        if self.pos < self.size:
            return Conv.byte_to_int(self.file_bytes.get('modified_byte')(self.pos))
        else:
            return -1
