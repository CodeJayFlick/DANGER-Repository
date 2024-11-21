class SourceArchiveUpgradeMap:
    OLD_CLIB_ARCHIVE_ID = 2585014296036210369
    OLD_WINDOWS_ARCHIVE_ID = 2592694847825635591
    OLD_NTDDK_ARCHIVE_ID = 2585014353215059675

    old_archive_ids = [OLD_CLIB_ARCHIVE_ID, OLD_NTDDK_ARCHIVE_ID, OLD_WINDOWS_ARCHIVE_ID]

    WINDOWS_CSPEC_ID = "windows"
    windows_map = {}
    default_map = {}

    def __init__(self):
        NEW_WINDOWS_SUPER_ARCHIVE_ID = 2644092282468053077
        NEW_DEFAULT_CLIB_ARCHIVE_ID = 2644097909188870631

        NEW_WINDOWS_SUPER_ARCHIVE_NAME = "windows_vs12_32"
        NEW_DEFAULT_CLIB_ARCHIVE_NAME = "generic_clib"

        new_windows_archive = {"id": NEW_WINDOWS_SUPER_ARCHIVE_ID, "name": NEW_WINDOWS_SUPER_ARCHIVE_NAME}
        new_default_clib_archive = {"id": NEW_DEFAULT_CLIB_ARCHIVE_ID, "name": NEW_DEFAULT_CLIB_ARCHIVE_NAME}

        self.windows_map[UniversalID(OLD_CLIB_ARCHIVE_ID)] = new_windows_archive
        self.windows_map[UniversalID(OLD_WINDOWS_ARCHIVE_ID)] = new_windows_archive
        self.windows_map[UniversalID(OLD_NTDDK_ARCHIVE_ID)] = new_windows_archive

        self.default_map[UniversalID(OLD_CLIB_ARCHIVE_ID)] = {"id": NEW_DEFAULT_CLIB_ARCHIVE_ID, "name": NEW_DEFAULT_CLIB_ARCHIVE_NAME}
        removed_source_archive = {"id": None, "name": ""}
        for old_id in old_archive_ids:
            if old_id not in [NEW_WINDOWS_SUPER_ARCHIVE_ID, NEW_DEFAULT_CLIB_ARCHIVE_ID]:
                self.default_map[UniversalID(old_id)] = removed_source_archive

    def get_mapped_source_archive(self, source_archive, compiler):
        if compiler is not None:
            compiler_spec_id = compiler.get_compiler_spec_id()
            if WINDOWS_CSPEC_ID == compiler_spec_id:
                replacement_source_archive = self.windows_map.get( UniversalID(source_archive["id"]) )
                return replacement_source_archive
        return self.default_map.get(UniversalID(source_archive["id"]))

    @staticmethod
    def is_replaced_source_archive(id):
        for old_id in SourceArchiveUpgradeMap.old_archive_ids:
            if id == old_id:
                return True
        return False

    @staticmethod
    def get_typedef_replacements():
        return ["short", "int", "long", "longlong", "wchar_t", "bool"]

class UniversalID:
    def __init__(self, id):
        self.id = id

class SourceArchiveImpl(SourceArchive):
    def __init__(self, id=None, name=""):
        if id is None:
            self.id = DataTypeManager.LOCAL_ARCHIVE UNIVERSAL_ID
        else:
            self.id = id
        self.name = name

    # Other methods...

