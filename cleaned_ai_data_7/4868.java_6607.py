class CFragUsage2Union:
    k_no_app_sub_folder = 0

    def __init__(self, reader):
        self.app_subdir_id = reader.read_short()

    @property
    def application_subdirectory_id(self):
        return self.app_subdir_id

    def to_data_type(self) -> tuple:
        from ghidra_util import StructConverterUtil
        try:
            return StructConverterUtil.to_data_type(type(self))
        except Exception as e:
            raise DuplicateNameException(str(e)) from None
