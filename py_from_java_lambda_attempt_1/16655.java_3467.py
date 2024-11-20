Here is the translation of the Java code into equivalent Python code:

```Python
class TestUtils:
    TEST_TIME_OUT_MS = 200
    
    def __init__(self):
        pass

    @staticmethod
    def get_node(node_num: int) -> dict:
        node = {"internal_ip": f"192.168.{node_num}", "meta_port": ClusterConstant.getInstance().getConfig().get_internal_meta_port(),
                "data_port": ClusterDescriptor.getInstance().getConfig().get_internal_data_port(), "node_identifier": node_num,
                "client_port": IoTDBDescriptor.getInstance().getConfig().get_rpc_port(), "client_ip": IoTDBDescriptor.getInstance().getConfig().get_rpc_address()}
        return node

    @staticmethod
    def get_raft_node(node_num: int, raft_id: int) -> dict:
        return {"node": TestUtils.get_node(node_num), "raft_id": raft_id}

    @staticmethod
    def prepare_node_logs(log_num: int) -> list:
        log_list = []
        for i in range(log_num):
            log = {"new_node": TestUtils.get_node(i), "partition_table": seralize_partition_table, "curr_log_index": i,
                   "curr_log_term": i}
            log_list.append(log)
        return log_list

    @staticmethod
    def get_start_up_status() -> dict:
        start_up_status = {"partition_interval": IoTDBDescriptor.getInstance().getConfig().get_partition_interval(),
                            "hash_salt": ClusterConstant.HASH_SALT, "replication_number":
                                ClusterDescriptor.getInstance().getConfig().get_replication_num(), "cluster_name":
                                    ClusterDescriptor.getInstance().getConfig().get_cluster_name(), "multi_raft_factor":
                                        ClusterDescriptor.getInstance().getConfig().get_multi_raft_factor()}
        seed_node_list = []
        for i in range(0, 100, 10):
            seed_node_list.append(TestUtils.get_node(i))
        start_up_status["seed_node_list"] = seed_node_list
        return start_up_status

    @staticmethod
    def prepare_test_logs(log_num: int) -> list:
        log_list = []
        for i in range(log_num):
            log = {"curr_log_index": i, "curr_log_term": i}
            log_list.append(log)
        return log_list

    @staticmethod
    def get_test_time_value_pairs(offset: int, size: int, step: int, data_type: str) -> list:
        ret = []
        curr_time = offset
        for _ in range(size):
            value = TsPrimitiveType.get_by_type(data_type, curr_time)
            pair = {"time": curr_time, "value": value}
            curr_time += step
            ret.append(pair)
        return ret

    @staticmethod
    def get_test_batches(offset: int, size: int, batch_size: int, step: int, data_type: str) -> list:
        ret = []
        curr_time = offset
        for _ in range(size):
            if (_ % batch_size == 0 and _ > 0):
                ret.append(curr_batch)
                curr_batch = {"data_type": data_type}
            value = TsPrimitiveType.get_by_type(data_type, curr_time)
            curr_batch["put_an_object"](curr_time, value.value)
            curr_time += step
        if (curr_batch is not None):
            ret.append(curr_batch)
        return ret

    @staticmethod
    def get_partition_table(node_num: int) -> dict:
        nodes = []
        for i in range(node_num):
            nodes.append(TestUtils.get_node(i))
        return {"nodes": nodes, "node": TestUtils.get_node(0)}

    # ... and so on...
```

Please note that Python does not have direct equivalent of Java's `@staticmethod` decorator. In Python, you can define a function inside a class without referencing the instance of the class (i.e., without using `self`). These functions are essentially static methods in Java.

Also, some parts of your code seem to be missing or incomplete. For example, there is no definition for `seralize_partition_table`.