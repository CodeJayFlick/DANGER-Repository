class GuidDataType:
    serialVersionUID = 1
    NAME = "GUID"
    SIZE = 16
    KEY = "GUID_NAME"

    ENDIAN = {"DEF": EndianSettingsDefinition()}

    SETTINGS_DEFS = [ENDIAN["DEF"]]

    cachedGuidString = None
    cachedGuidName = None

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__(None, NAME, dtm)
        if dtm is not None:
            return

    @property
    def mnemonic(self):
        return self.NAME

    @property
    def length(self):
        return self.SIZE

    @property
    def description(self):
        return self.NAME

    def get_value(self, buf, settings, length):
        return self.get_string(buf, settings)

    def get_representation(self, buf, settings, length):
        return self.get_string(buf, settings)

    def get_builtin_settings_definitions(self):
        return [self.ENDIAN["DEF"]]

    def get_string(self, buf, settings):
        guid_name = settings.get_value(self.KEY)
        delim = "-"
        bytes = bytearray(16)
        data = [0] * 4

        is_big_endian = self.ENDIAN["DEF"].is_big_endian(settings, buf)

        if buf.readinto(bytes) != len(bytes):
            if guid_name:
                return str(guid_name)
            return "??"

        for i in range(len(data)):
            data[i] = (0xFFFFFFFF & int.from_bytes(bytes[i * 4:i * 4 + 4], byteorder="big")) >> ((3 - i) * 8)

        ret_val = ""
        for d in data:
            ret_val += hex(d)[2:] + delim
        return ret_val[:-1]

    def get_guid_name(self, guid_string):
        if self.cachedGuidString == guid_string:
            return self.cachedGuidName

        self.cachedGuidString = guid_string
        guid_info = GuidUtil.get_known_guid(guid_string)
        if guid_info is not None:
            self.cachedGuidName = guid_info.name()
        else:
            self.cachedGuidName = None
        return self.cachedGuidName

    def get_default_label_prefix(self):
        return self.NAME

    def clone(self, dtm=None):
        if dtm == self.get_data_type_manager():
            return self
        return GuidDataType(dtm)
