Here is the translation of the Java code into Python:

```Python
class GuidType:
    def __init__(self, filename, has_version):
        self.filename = filename
        self.has_version = has_version

    def get_filename(self):
        return self.filename

    def has_version(self):
        return self.has_version


class GuidInfo:
    def __init__(self, guid_string, name, guid_type):
        self.guid_string = guid_string
        self.name = name
        self.guid_type = guid_type

    def get_unique_id_string(self):
        return self.guid_string

    def get_name(self):
        return self.name


class VersionedGuidInfo(GuidInfo):
    def __init__(self, guid_string, version, name, guid_type):
        super().__init__(guid_string, name, guid_type)
        self.version = version

    def get_version(self):
        return self.version


def initialize():
    global id_tables
    if not initialized:
        id_tables = {}
        for guid_type in guid_types:
            id_tables[guid_type] = {}
        build_guid_map()
        initialized = True


def read_guid_file(guid_type, filename, table):
    try:
        dir = Application.get_module_data_subdirectory(ARCHIVE_DIR_PARENT + "/" + ARCHIVE_DIR)
        infile = ResourceFile(dir, filename)
        if not infile.exists():
            Msg.error(GuidUtil.__class__, "ERROR: file not found: " + filename)
            return
        input = BufferedReader(InputStreamReader(infile.getInputStream()))
        inline
        while (inline := input.readline()) is not None:
            if not inline.startswith("#") and len(inline) >= 30:
                guid_info = parse_line(inline, "-", guid_type)
                if guid_info is not None:
                    table[guid_info.get_unique_id_string()] = guid_info
    except IOException as e1:
        Msg.error(GuidUtil.__class__, "Unexpected Exception: " + str(e1), e1)


def parse_line(guid_name_line, delim, guid_type):
    global NUM_BYTES
    data = [0] * 4
    version = None
    name

    has_version = guid_type.has_version()
    guid_string = guid_name_line.replace("\t", " ")
    stripped_guid = guid_string[:guid_string.index(" ")].replace(delim, "")
    if len(stripped_guid) != NUM_BYTES * 2:
        Msg.error(GuidUtil.__class__, "ERROR PARSING GUID: " + guid_name_line)
        return None
    data[0] = (0xFFFFFFFFL & parse_hex_long(stripped_guid[:8]))
    str = stripped_guid[8:16]
    str = str[4:8] + str[:4]
    data[1] = (0xFFFFFFFFL & parse_hex_long(str))
    str = stripped_guid[16:24]
    str = str[6:8] + str[4:6] + str[2:4] + str[:2]
    data[2] = (0xFFFFFFFFL & parse_hex_long(str))
    str = stripped_guid[24:]
    if has_version:
        vpos = left.index("v")
        if vpos > 0:
            left = left[vpos:]
            sppos = left.index(" ")
            if sppos > 0:
                version = left[:sppos]
            else:
                version = left[:]
            left = left[sppos + 1:]
    name = left[left.index(" ") + 1:]

    return GuidInfo(guid_string, name, guid_type) if is_ok(data) and not has_version else VersionedGuidInfo(
        guid_string, version, name, guid_type)


def is_ok(data):
    for element in data:
        if (element != 0 or element != 0xFFFFFFFFL):
            return True
    return False


def get_guid_string(program, address, validate):
    delim = "-"
    bytes = [0] * 16
    data = [0] * 4
    is_big_endian = program.get_memory().is_big_endian()
    conv = DataConverter(is_big_endian)

    try:
        program.get_memory().get_bytes(address, bytes)
        for i in range(len(data)):
            data[i] = (0xFFFFFFFFL & conv.get_int(bytes, i * 4))
            conv.get_bytes((int) data[i], bytes, i * 4)
    except MemoryAccessException as e:
        return None

    guid_string = ""
    for i in range(4):
        guid_string += Conv.to_hex_string((byte)(data[2] >> i * 8)) + delim
    for i in range(4):
        guid_string += Conv.to_hex_string((byte)(data[3] >> i * 8))

    if validate and not NewGuid.is_ok_for_guid(bytes, 0):
        return None

    return guid_string


def get_versioned_guid_string(program, address, validate):
    delim = "-"
    bytes = [0] * 20
    data = [0] * 4
    version_data = [0] * 2
    is_big_endian = program.get_memory().is_big_endian()
    conv = DataConverter(is_big_endian)

    try:
        program.get_memory().get_bytes(address, bytes)
        for i in range(len(data)):
            data[i] = (0xFFFFFFFFL & conv.get_int(bytes, i * 4))
            conv.get_bytes((int) data[i], bytes, i * 4)
    except MemoryAccessException as e:
        return None

    guid_string = ""
    for i in range(4):
        guid_string += Conv.to_hex_string((byte)(data[2] >> i * 8)) + delim
    for i in range(4):
        guid_string += Conv.to_hex_string((byte)(data[3] >> i * 8))

    guid_string += " v"
    version_data[0] = (bytes[17] << 8) + bytes[16]
    guid_string += str(version_data[0]) + "."
    version_data[1] = (bytes[19] << 8) + bytes[18]
    guid_string += str(version_data[1])

    if validate and not NewGuid.is_ok_for_guid(bytes, 0):
        return None

    return guid_string


def is_guid_label(program, address, label):
    if not label.startswith(MS_GUID_PREFIX):
        return False
    guid_string = label[len(MS_GUID_PREFIX):].replace("_", "-")
    try:
        GUID(guid_string)
    except Exception as e:
        return False
    dt = GuidDataType()
    guid_rep = dt.get_representation(DumbMemBufferImpl(program.get_memory(), address), SettingsImpl(), -1)
    return guid_rep.endswith(guid_string)


class ResourceFile:
    def __init__(self, dir, filename):
        self.dir = dir
        self.filename = filename

    def exists(self):
        pass


class BufferedReader:
    def __init__(self, input_stream_reader):
        self.input_stream_reader = input_stream_reader

    def read_line(self):
        pass


class DataConverter:
    def __init__(self, is_big_endian):
        self.is_big_endian = is_big_endian

    def get_int(self, bytes, offset):
        pass

    def get_bytes(self, value, bytes, offset):
        pass
```

Please note that the above Python code does not include all the classes and methods from the original Java code. It only includes those parts which are directly translatable to Python without significant changes in logic or functionality.