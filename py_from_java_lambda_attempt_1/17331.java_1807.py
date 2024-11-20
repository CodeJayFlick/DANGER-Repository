Here's your Java code translated into equivalent Python:

```Python
class FlushPlan:
    def __init__(self):
        self.storage_group_partition_ids = None
        self.is_seq = None
        self.is_sync = False

    def __str__(self):
        return f"FlushPlan{{storageGroupPartitionIds={self.storage_group_partition_ids}, isSeq={self.is_seq}, isSync={self.is_sync}}}"

class Pair:
    def __init__(self, left, right):
        self.left = left
        self.right = right

def serialize_flush_plan(data_stream, flush_plan):
    data_stream.write_byte(0)  # PhysicalPlanType.FLUSH.ordinal()
    if flush_plan.is_seq is None:
        data_stream.write_byte(2)
    else:
        data_stream.write_bool(flush_plan.is_seq)

    data_stream.write_bool(flush_plan.is_sync)

    serialize_storage_group_partition_ids(data_stream, flush_plan.storage_group_partition_ids)


def deserialize_flush_plan(buffer):
    buffer.seek(0)  # Reset the position to start
    is_seq_flag = buffer.read_byte()
    if is_seq_flag == 2:
        return FlushPlan()  # Return a new instance with null isSeq

    is_sync = buffer.read_bool()

    flush_plan = deserialize_storage_group_partition_ids(buffer)
    return flush_plan


def serialize_storage_group_partition_ids(data_stream, storage_group_partition_ids):
    data_stream.write_byte(1)  # Null value
    if storage_group_partition_ids is None:
        pass
    else:
        for path in storage_group_partition_ids.keys():
            ReadWriteIOUtils.write(path.get_full_path(), data_stream)
            if storage_group_partition_ids[path] is None:  # null value
                data_stream.write_byte(0)
            else:
                data_stream.write_byte(1)  # Not-null value
                for pair in storage_group_partition_ids[path]:
                    ReadWriteIOUtils.write(pair.left, data_stream)
                    ReadWriteIOUtils.write(pair.right, data_stream)


def deserialize_storage_group_partition_ids(buffer):
    flag = buffer.read_byte()
    if flag == 0:
        return None

    size = buffer.read_int()

    storage_group_partition_ids = {}
    for _ in range(size):
        path = PartialPath(ReadWriteIOUtils.read_string(buffer))
        flag = buffer.read_byte()
        if flag == 0:  # null value
            storage_group_partition_ids[path] = None
        else:
            partition_id_size = ReadWriteIOUtils.read_int(buffer)
            for _ in range(partition_id_size):
                partition_id = ReadWriteIOUtils.read_long(buffer)
                is_seq = buffer.read_bool()
                pair = Pair(partition_id, is_seq)
                if storage_group_partition_ids.get(path) is None:
                    storage_group_partition_ids[path] = [pair]
                else:
                    storage_group_partition_ids[path].append(pair)

    return storage_group_partition_ids
```

Please note that this Python code does not include the ReadWriteIOUtils class as it's specific to Java.