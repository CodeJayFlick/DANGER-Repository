import logging
from typing import List

class SyncSenderConfig:
    def __init__(self):
        self.server_ip = None
        self.server_port = 0
        self.sync_period_in_second = 0
        self.storage_group_list: List[str] = []
        self.max_num_of_sync_file_retry = 0

class SyncSenderDescriptor:
    _logger = logging.getLogger(__name__)
    _conf = SyncSenderConfig()

    def __init__(self):
        self.load_props()

    @classmethod
    def get_instance(cls) -> 'SyncSenderDescriptor':
        return cls._instance

    @property
    def config(self) -> SyncSenderConfig:
        return self._conf

    @config.setter
    def set_config(self, conf: SyncSenderConfig):
        self._conf = conf

    def load_props(self):
        url = os.environ.get('IOTDB_CONF', None)
        if not url:
            home_dir = os.environ.get('IOTDB_HOME', None)
            if home_dir:
                url = f"{home_dir}/conf/{SyncConstant.CONFIG_NAME}"
            else:
                self._logger.warning("Cannot find IOTDB_HOME or IOTDB_CONF environment variable when loading config file, using default configuration")
                return

        try:
            with open(url) as input_stream:
                properties = Properties()
                properties.load(input_stream)

                self._conf.server_ip = properties.get('server_ip', self._conf.server_ip)
                self._conf.server_port = int(properties.get('server_port', str(self._conf.server_port)))
                self._conf.sync_period_in_second = int(properties.get('sync_period_in_second', str(self._conf.sync_period_in_second)))

                storage_groups = properties.get('sync_storage_groups')
                if storage_groups:
                    splits = [sg.strip() for sg in storage_groups.split(',')]
                    self._conf.storage_group_list = splits
                else:
                    self._conf.storage_group_list = []

                self._conf.max_num_of_sync_file_retry = int(properties.get('max_number_of_sync_file_retry', str(self._conf.max_num_of_sync_file_retry)))

        except FileNotFoundError as e:
            self._logger.warning(f"Fail to find sync config file {url}, using default configuration", e)
        except Exception as e:
            self._logger.error("Error format in sync config file, using default sync configuration.", e)

class SyncSenderDescriptorHolder:
    _instance = SyncSenderDescriptor()
