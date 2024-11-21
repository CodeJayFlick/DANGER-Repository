class IndexType:
    NO_INDEX = 'NO_INDEX'
    RTREE_PAA = 'RTREE_PAA'
    ELB_INDEX = 'ELB_INDEX'
    KV_INDEX = 'KV_INDEX'

def deserialize(i):
    if i == 0:
        return IndexType.NO_INDEX
    elif i == 1:
        return IndexType.RTREE_PAA
    elif i == 2:
        return IndexType.ELB_INDEX
    elif i == 3:
        return IndexType.KV_INDEX
    else:
        raise NotImplementedError("Given index is not implemented")

def get_serialized_size():
    return 2

def serialize(this):
    if this == IndexType.NO_INDEX:
        return 0
    elif this == IndexType.RTREE_PAA:
        return 1
    elif this == IndexType.ELB_INDEX:
        return 2
    elif this == IndexType.KV_INDEX:
        return 3
    else:
        raise NotImplementedError("Given index is not implemented")

def get_index_type(index_type_string):
    try:
        return getattr(IndexType, index_type_string.upper())
    except AttributeError as e:
        raise ValueError(f"Unsupported index type: {index_type_string}")
