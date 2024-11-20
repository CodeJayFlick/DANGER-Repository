class ServiceType:
    STORAGE_ENGINE_SERVICE = ("Storage Engine ServerService", "")
    JMX_SERVICE = ("JMX ServerService", "JMX ServerService")
    METRICS_SERVICE = ("Metrics ServerService", "MetricsService")
    RPC_SERVICE = ("RPC ServerService", "RPCService")
    MQTT_SERVICE = ("MQTTService", "")
    MONITOR_SERVICE = ("Monitor ServerService", "Monitor")
    STAT_MONITOR_SERVICE = ("Statistics ServerService", "")
    WAL_SERVICE = ("WAL ServerService", "")
    CLOSE_MERGE_SERVICE = ("Close&Merge ServerService", "")
    JVM_MEM_CONTROL_SERVICE = ("Memory Controller", "")
    AUTHORIZATION_SERVICE = ("Authorization ServerService", "")
    FILE_READER_MANAGER_SERVICE = ("File reader manager ServerService", "")
    SYNC_SERVICE = ("SYNC ServerService", "")
    UPGRADE_SERVICE = ("UPGRADE DataService", "")
    SETTLE_SERVICE = ("SETTLE DataService", "")
    MERGE_SERVICE = ("Merge Manager", "Merge Manager")
    COMPACTION_SERVICE = ("Compaction Manager", "Compaction Manager")
    PERFORMANCE_STATISTIC_SERVICE = (
        "PERFORMANCE_STATISTIC_ SERVICE",
        "PERFORMANCE_STATISTIC_ SERVICE"
    )
    TVLIST_ALLOCATOR_SERVICE = ("TVList Allocator", "")
    UDF_CLASSLOADER_MANAGER_SERVICE = ("UDF Classloader Manager Service", "")
    UDF_REGISTRATION_SERVICE = ("UDF Registration Service", "")
    TEMPORARY_QUERY_DATA_FILE_SERVICE = (
        "Temporary Query Data File Service",
        ""
    )
    TRIGGER_REGISTRATION_SERVICE = ("Trigger Registration Service", "")
    CACHE_HIT_RATIO_DISPLAY_SERVICE = (
        "CACHE_ HIT_RATIO_ DISPLAY_ SERVICE",
        f"Cache Hit Ratio ({IoTDBConstant.IOTDB_PACKAGE}, 'Cache Hit Ratio'))"
    QUERY_TIME_MANAGER = ("Query time manager", "Query time")

    FLUSH_SERVICE = (
        "Flush ServerService",
        f"{generate_jmx_name('org.apache.iotdb.db.engine.pool', 'Flush Manager')}"
    )
    CLUSTER_MONITOR_SERVICE = ("Cluster Monitor ServerService", "Cluster Monitor")
    SYSTEMINFO_SERVICE = ("MemTable Monitor Service", "MemTable, Monitor")
    CONTINUOUS_QUERY_SERVICE = (
        "Continuous Query Service",
        "Continuous Query Service"
    )
    CLUSTER_INFO_SERVICE = (
        "Cluster Monitor Service (thrift-based)",
        "Cluster Monitor-Thrift"
    )

    def __init__(self, name: str, jmx_name: str):
        self.name = name
        self.jmx_name = jmx_name

    @property
    def name(self) -> str:
        return self._name

    @property
    def jmx_name(self) -> str:
        return self._jmx_name


def generate_jmx_name(package_name: str, jmx_name: str):
    return f"{package_name}:type={jmx_name}"
