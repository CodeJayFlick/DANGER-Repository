Here's your Java code translated into Python:

```Python
class ISO9660PathTable:
    def __init__(self, reader, little_endian):
        self.little_endian = little_endian
        self.volume_index = reader.tell()
        self.dir_identifier_length = reader.read(1)[0]
        self.extended_attribute_record_length = reader.read(1)[0]
        self.location_of_extent = int.from_bytes(reader.read(4), byteorder='little' if little_endian else 'big')
        self.directory_number_path_index = int.from_bytes(reader.read(2), byteorder='little' if little_endian else 'big')

        directory_identifier_length_in_bytes = self.dir_identifier_length
        self.directory_identifier = reader.read(directory_identifier_length_in_bytes)

        # The padding field is only present if the dirIdentifierLength is odd, otherwise it's not used.
        if directory_identifier_length_in_bytes % 2 != 0:
            self.padding_field = reader.read(1)[0]
            self.padding_field_present = True
        else:
            self.padding_field_present = False

    def to_data_type(self):
        structure = {
            'Directory Identifier Length': {'type': 'byte', 'value': self.dir_identifier_length},
            'Extended Attribute Record Length': {'type': 'byte', 'value': self.extended_attribute_record_length},
            'Location of Extent (LBA)': {'type': 'int', 'value': self.location_of_extent},
            'Directory Number': {'type': 'short', 'value': self.directory_number_path_index},
            'Directory Identifier': {'type': 'bytes', 'value': bytes(self.directory_identifier)},
        }

        if not self.little_endian:
            structure['Location of Extent (LBA)']['byteorder'] = 'big'

        return structure

    def __str__(self):
        buff = []

        buff.append(f"Directory Identifier Length: 0x{self.dir_identifier_length:x}")
        buff.append(f"Extended Attribute Record Length: {self.extended_attribute_record_length:x}")
        buff.append(f"Location of Extent (LBA): 0x{self.location_of_extent:x}")
        buff.append(f"Directory Number: 0x{self.directory_number_path_index:x}")
        buff.append(f"Directory Identifier: {''.join(map(chr, self.directory_identifier))}".strip())
        if self.padding_field_present:
            buff.append(f"Padding Field: 0x{self.padding_field:x}")

        return '\n'.join(buff)

    def get_dir_identifier_length(self):
        return self.dir_identifier_length

    def get_extended_attribute_record_length(self):
        return self.extended_attribute_record_length

    def get_location_of_extent(self):
        return self.location_of_extent

    def get_directory_number_path_index(self):
        return self.directory_number_path_index

    def get_directory_identifier(self):
        return bytes(self.directory_identifier)

    def get_padding_field(self):
        return self.padding_field

    def is_padding_field_present(self):
        return self.padding_field_present

    def get_volume_index(self):
        return self.volume_index

    def is_little_endian(self):
        return self.little_endian
```

This Python code defines a class `ISO9660PathTable` that has methods to read and write the fields of an ISO 9660 path table. The constructor takes two parameters: a reader object (which should have methods for reading bytes, shorts, ints, etc.) and a boolean indicating whether the data is in little-endian or big-endian format.