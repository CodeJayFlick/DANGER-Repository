import io


class DexSectionHeader002:
    def __init__(self, reader):
        self.dex_size = int.from_bytes(reader.read(4), 'little')
        self.dex_shared_data_size = int.from_bytes(reader.read(4), 'little')
        self.quickening_info_size = int.from_bytes(reader.read(4), 'little')

    @property
    def dex_size(self):
        return self._dex_size

    @property
    def dex_shared_data_size(self):
        return self._dex_shared_data_size

    @property
    def quickening_info_size(self):
        return self._quickening_info_size


def to_data_type():
    try:
        data_type = StructConverterUtil.to_data_type(DexSectionHeader002)
        data_type.set_category_path('/vdex')
        return data_type
    except (DuplicateNameException, io.IOException) as e:
        raise e

