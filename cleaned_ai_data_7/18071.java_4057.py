import logging
from io import File
from typing import List

class EnvironmentUtils:
    creation_sqls = [
        "SET STORAGE GROUP TO root.vehicle.d0",
        "SET STORAGE GROUP TO root.vehicle.d1",
        "CREATE TIMESERIES root.vehicle.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE",
        # ... (rest of the SQL statements)
    ]

    data_set2 = [
        "SET STORAGE GROUP TO root.ln.wf01.wt01",
        "CREATE TIMESERIES root.ln.wf01.wt01.status WITH DATATYPE=BOOLEAN, ENCODING=PLAIN",  # ... (rest of the SQL statements)
    ]

    insert_template = "INSERT INTO root.vehicle.d0( timestamp, s0, s1, s2, s3, s4) VALUES(%d, %d, %d, %f, '%s', '%s')"

    logger = logging.getLogger(__name__)

    def __init__(self):
        self.config = IoTDBConfig()
        self.directory_manager = DirectoryManager()

    @staticmethod
    def clean_env():
        # ... (rest of the code)

    @staticmethod
    def close_stat_monitor():
        EnvironmentUtils.logger.info("Disabling system monitor")
        EnvironmentUtils.config.set_enable_stat_monitor(False)

    @staticmethod
    def env_setup():
        try:
            authorizer = BasicAuthorizer()
        except AuthException as e:
            raise StartupException(e)
        # ... (rest of the code)

    @staticmethod
    def create_all_dir():
        for path in EnvironmentUtils.directory_manager.get_all_sequence_file_folders():
            File(path).mkdirs()

    @staticmethod
    def prepare_data():
        try:
            connection = DriverManager.getConnection("127.0.0.1:6667", "root", "root")
            statement = connection.createStatement()
            # ... (rest of the code)
