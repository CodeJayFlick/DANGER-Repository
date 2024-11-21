import logging
from typing import List, Dict, Any

class ClusterUtils:
    def __init__(self):
        pass  # util class

    WAIT_START_UP_CHECK_TIME_SEC = 5
    START_UP_TIME_THRESHOLD_MS = 30000  # 30 seconds * 1000 milliseconds per second
    START_UP_CHECK_TIME_INTERVAL_MS = 3000  # 3 seconds * 1000 milliseconds per second

    DATA_HEARTBEAT_PORT_OFFSET = 1
    META_HEARTBEAT_PORT_OFFSET = 1

    UNKNOWN_CLIENT_IP = "UNKNOWN_IP"

    @staticmethod
    def check_status(remote_start_up_status: Any, local_start_up_status: Any) -> Dict[str, bool]:
        partition_interval_equals = True
        hash_salt_equals = True
        replication_num_equals = True
        seed_node_list_equals = True
        cluster_name_equal = True
        multi_raft_factor_equal = True

        if remote_start_up_status.get_partition_interval() != local_start_up_status.get_partition_interval():
            logging.error("Remote partition interval conflicts with local. Local: {}, Remote: {}", 
                          local_start_up_status.get_partition_interval(), 
                          remote_start_up_status.get_partition_interval())
            partition_interval_equals = False
        if remote_start_up_status.get_multi_raft_factor() != local_start_up_status.get_multi_raft_factor():
            logging.error("Remote multi-raft factor conflicts with local. Local: {}, Remote: {}", 
                          local_start_up_status.get_multi_raft_factor(), 
                          remote_start_up_status.get_multi_raft_factor())
            multi_raft_factor_equal = False
        if remote_start_up_status.get_hash_salt() != local_start_up_status.get_hash_salt():
            logging.error("Remote hash salt conflicts with local. Local: {}, Remote: {}", 
                          local_start_up_status.get_hash_salt(), 
                          remote_start_up_status.get_hash_salt())
            hash_salt_equals = False
        if remote_start_up_status.get_replication_number() != local_start_up_status.get_replication_number():
            logging.error("Remote replication number conflicts with local. Local: {}, Remote: {}", 
                          local_start_up_status.get_replication_number(), 
                          remote_start_up_status.get_replication_number())
            replication_num_equals = False
        if not Objects.equals(local_start_up_status.get_cluster_name(), remote_start_up_status.get_cluster_name()):
            logging.error("Remote cluster name conflicts with local. Local: {}, Remote: {}", 
                          local_start_up_status.get_cluster_name(), 
                          remote_start_up_status.get_cluster_name())
            cluster_name_equal = False
        if not ClusterUtils.check_seed_nodes(False, local_start_up_status.get_seed_node_list(), remote_start_up_status.get_seed_node_list()):
            seed_node_list_equals = False

        return {
            "partition_interval_equals": partition_interval_equals,
            "hash_salt_equals": hash_salt_equals,
            "replication_num_equals": replication_num_equals,
            "seed_node_list_equals": seed_node_list_equals,
            "cluster_name_equal": cluster_name_equal,
            "multi_raft_factor_equal": multi_raft_factor_equal
        }

    @staticmethod
    def check_seed_nodes(is_cluster_established: bool, local_seed_nodes: List[Any], remote_seed_nodes: List[Any]) -> bool:
        if is_cluster_established:
            return seed_nodes_contains(local_seed_nodes, remote_seed_nodes)
        else:
            return seed_nodes_equals(local_seed_nodes, remote_seed_nodes)

    @staticmethod
    def examine_check_status_response(response: Dict[str, bool], consistent_num: int, inconsistent_num: int, seed_node: Any) -> None:
        if not response["partition_interval_equals"]:
            logging.error("Local partition interval conflicts with seed node[{}].", seed_node)
        if not response["hash_salt_equals"]:
            logging.error("Local hash salt conflicts with seed node[{}]", seed_node)
        if not response["replication_num_equals"]:
            logging.error("Local replication number conflicts with seed node[{}]", seed_node)
        if not response["seed_node_list_equals"]:
            logging.error("Local seed node list conflicts with seed node[{}]", seed_node)
        if not response["cluster_name_equal"]:
            logging.error("Local cluster name conflicts with seed node[{}]", seed_node)

    @staticmethod
    def analyse_start_up_check_result(consistent_num: int, inconsistent_num: int, total_seed_num: int) -> bool:
        if consistent_num == total_seed_num:
            return True  # break the loop and establish the cluster
        elif inconsistent_num > 0:
            raise ConfigInconsistentException()  # find config InConsistence, stop building cluster
        else:
            return False  # The status of some nodes was not obtained, possibly because those node did not start

    @staticmethod
    def create_t_thread_pool_server(socket: Any, client_thread_prefix: str, processor: Any, protocol_factory: Any) -> Any:
        config = ClusterDescriptor.getInstance().getConfig()
        max_concurrent_client_num = max(CommonUtils.getCpuCores(), config.getMaxConcurrentClientNum())
        pool_args = TThreadPoolServer.Args(socket)
        pool_args.max_worker_threads(max_concurrent_client_num)
        pool_args.min_worker_threads(CommonUtils.getCpuCores())

    @staticmethod
    def string_to_node(str: str) -> Any:
        ip_first_pos = str.index("internalIp:") + "internalIp:".length()
        ip_last_pos = str.index(',', ip_first_pos)
        meta_port_first_pos = str.index("metaPort:", ip_last_pos) + "metaPort:".length()
        meta_port_last_pos = str.index(',', meta_port_first_pos)
        id_first_pos = str.index("nodeIdentifier:", meta_port_last_pos) + "nodeIdentifier:".length()
        id_last_pos = str.index(',', id_first_pos)
        data_port_first_pos = str.index("dataPort:", id_last_pos) + "dataPort:".length()
        data_port_last_pos = str.index(',', data_port_first_pos)
        client_port_first_pos = str.index("clientPort:", data_port_last_pos) + "clientPort:".length()
        client_port_last_pos = str.index(',', client_port_first_pos)
        client_ip_first_pos = str.index("clientIp:", client_port_last_pos) + "clientIp:".length()
        client_ip_last_pos = str.index(')', client_ip_first_pos)

        ip = str[ip_first_pos:ip_last_pos]
        meta_port = int(str[meta_port_first_pos:meta_port_last_pos])
        id = int(str[id_first_pos:id_last_pos])
        data_port = int(str[data_port_first_pos:data_port_last_pos])
        client_port = int(str[client_port_first_pos:client_port_last_pos])
        client_ip = str[client_ip_first_pos:client_ip_last_pos]
        return Node(ip, meta_port, id, data_port, client_port, client_ip)

    @staticmethod
    def parse_node(node_url: str) -> Any:
        result = new Node()
        split = node_url.split(":")
        if len(split) != 2:
            logging.warn("Bad seed url: {}", node_url)
            return None

        ip = split[0]
        try:
            meta_port = int(split[1])
            result.set_internal_ip(ip).set_meta_port(meta_port).set_client_ip(UNKNOWN_CLIENT_IP)
        except NumberFormatException as e:
            logging.warn("Bad seed url: {}", node_url)

        return result
