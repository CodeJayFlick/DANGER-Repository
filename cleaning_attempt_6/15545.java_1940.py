class DataType:
    FLOAT32 = (Format.FLOATING, 4)
    FLOAT64 = (Format.FLOATING, 8)
    FLOAT16 = (Format.FLOATING, 2)
    UINT8 = (Format.UINT, 1)
    INT32 = (Format.INT, 4)
    INT8 = (Format.INT, 1)
    INT64 = (Format.INT, 8)
    BOOLEAN = (Format.BOOLEAN, 1)
    STRING = (Format.STRING, -1)
    UNKNOWN = (Format.UNKNOWN, 0)

    class Format:
        FLOATING
        UINT
        INT
        BOOLEAN
        STRING
        UNKNOWN

class NDArray:
    pass


def get_num_of_bytes(data_type):
    return data_type[1]


def is_floating(data_type):
    return data_type[2] == DataType.Format.FLOATING


def is_integer(data_type):
    return data_type[2] in [DataType.Format.UINT, DataType.Format.INT]


def from_buffer(data):
    if isinstance(data, float):
        return DataType.FLOAT32
    elif isinstance(data, int):
        return DataType.INT8
    else:
        raise ValueError("Unsupported buffer type")


def from_numpy(dtype):
    dtype_map = {
        "<f4": DataType.FLOAT32,
        ">f4": DataType.FLOAT32,
        "=f4": DataType.FLOAT32,
        "<f8": DataType.FLOAT64,
        ">f8": DataType.FLOAT64,
        "=f8": DataType.FLOAT64,
        "<f2": DataType.FLOAT16,
        ">f2": DataType.FLOAT16,
        "=f2": DataType.FLOAT16,
        "|u1": DataType.UINT8,
        "<i4": DataType.INT32,
        ">i4": DataType.INT32,
        "=i4": DataType.INT32,
        "|i1": DataType.INT8,
        "<i8": DataType.INT64,
        ">i8": DataType.INT64,
        "=i8": DataType.INT64,
        "|b1": DataType.BOOLEAN,
        "|S1": DataType.STRING
    }
    return dtype_map.get(dtype, None)


def as_data_type(data):
    if isinstance(data, float) and 0.0 <= data < 10.0:
        return DataType.FLOAT16.as_short_buffer()
    elif isinstance(data, int):
        return data.astype(int)
    else:
        raise ValueError("Unsupported buffer type")


def to_numpy(self):
    order = '<' if sys.byteorder == 'little' else '>'
    dtype_map = {
        DataType.FLOAT32: f"{order}f4",
        DataType.FLOAT64: f"{order}f8",
        DataType.FLOAT16: f"{order}f2",
        DataType.UINT8: "|u1",
        DataType.INT32: f"{order}i4",
        DataType.INT8: "|i1",
        DataType.INT64: "<i8",
        DataType.BOOLEAN: "|b1",
        DataType.STRING: "|S1"
    }
    return dtype_map[self]


def __str__(self):
    return self.name().lower()
