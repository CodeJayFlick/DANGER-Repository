import logging
from urllib.parse import urlparse

class HDFSConfUtil:
    ts_file_config = TSFileDescriptor().get_instance().get_config()
    logger = logging.getLogger(__name__)

    @staticmethod
    def set_conf(conf):
        if not ts_file_config.get_tsfile_storage_fs() == "HDFS":
            return conf
        
        try:
            core_site_url = urlparse(ts_file_config.get_core_site_path()).to_url()
            hdfs_site_url = urlparse(ts_file_config.get_hdfs_site_path()).to_url()
            conf.add_resource(core_site_url)
            conf.add_resource(hdfs_site_url)
        except ValueError as e:
            logger.error("Failed to add resource core-site.xml {} and hdfs-site.xml {}. {}".format(
                ts_file_config.get_core_site_path(), 
                ts_file_config.get_hdfs_site_path(),
                str(e)))

        conf.set("fs.hdfs.impl", "org.apache.hadoop.hdfs.DistributedFileSystem")
        conf.set("dfs.client.block.write.replace-datanode-on-failure.policy", "NEVER")
        conf.set("dfs.client.block.write.replace-datanode-on-failure.enable", True)

        # HA configuration
        hdfs_ips = ts_file_config.get_hdfs_ip()
        if len(hdfs_ips) > 1:
            dfs_nameservices = ts_file_config.get_dfs_name_services()
            dfs_ha_namenodes = ts_file_config.get_dfs_ha_namenodes()
            conf.set("dfs.nameservices", dfs_nameservices)
            conf.set("dfs.ha.namenodes." + dfs_nameservices, ",".join(dfs_ha_namenodes))
            for i in range(len(dfs_ha_namenodes)):
                conf.set(
                    "dfs.namenode.rpc-address." 
                    + dfs_nameservices
                    + TSFileConstant.PATH_SEPARATOR
                    + dfs_ha_namenodes[i].strip(),
                    "{}:{}".format(hdfs_ips[i], ts_file_config.get_hdfs_port())
                )
            dfs_ha_automatic_failover_enabled = ts_file_config.is_dfs_ha_automatic_failover_enabled()
            conf.set("dfs.ha.automatic-failover.enabled", str(dfs_ha_automatic_failover_enabled))
            if dfs_ha_automatic_failover_enabled:
                conf.set(
                    "dfs.client.failover.proxy.provider." + dfs_nameservices,
                    ts_file_config.get_dfs_client_failover_proxy_provider()
                )

        # Kerberos configuration
        if ts_file_config.use_kerberos():
            conf.set("hadoop.security.authorization", True)
            conf.set("hadoop.security.authentication", "kerberos")
            conf.set("dfs.block.access.token.enable", True)

            try:
                UserGroupInformation.login_user_from_keytab(
                    ts_file_config.get_kerberos_principal(), 
                    ts_file_config.get_kerberos_keytab_file_path()
                )
            except Exception as e:
                logger.error("Failed to login user from key tab. User: {}, path:{}.".format(
                    ts_file_config.get_kerberos_principal(),
                    ts_file_config.get_kerberos_keytab_file_path()),
                    str(e))

        return conf
