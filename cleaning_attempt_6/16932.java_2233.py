import os
import shutil
from logging import Logger, getLogger

class IoTDBConfigCheck:
    def __init__(self):
        self.logger = getLogger(__name__)

    @staticmethod
    def getInstance():
        return IoTDBConfigCheckHolder.INSTANCE

    class IoTDBConfigCheckHolder:
        INSTANCE = IoTDBConfigCheck()

    def __init__(self):
        self.logger.info("Starting IoTDB " + IoTDBConstant.VERSION)

        if not os.path.exists(IoTDBConfigCheck.SCHEMA_DIR):
            try:
                os.makedirs(IoTDBConfigCheck.SCHEMA_DIR)
                self.logger.info("{} dir has been created.".format(IoTDBConfigCheck.SCHEMA_DIR))
            except Exception as e:
                self.logger.error("can not create schema dir: {}".format(e))

        if timestamp_precision != "ms" and timestamp_precision != "us" and timestamp_precision != "ns":
            self.logger.error(
                "Wrong {}, please set as: ms, us or ns  ! Current is: {}.".format(TIMESTAMP_PRECISION_STRING, timestamp_precision)
            )
            exit(-1)

        if not enable_partition:
            partition_interval = long.MAX_VALUE

        if partition_interval <= 0:
            self.logger.error("Partition interval must larger than 0!")
            exit(-1)

    def checkConfig(self):
        properties_file = os.path.join(IoTDBConfigCheck.SCHEMA_DIR, PROPERTIES_FILE_NAME)
        tmp_properties_file = os.path.join(IoTDBConfigCheck.SCHEMA_DIR, PROPERTIES_FILE_NAME + ".tmp")

        if not os.path.exists(properties_file) and not os.path.exists(tmp_properties_file):
            try:
                with open(properties_file, "w") as f:
                    for k, v in system_properties.items():
                        properties.setProperty(k, v)
                    properties.store(f, SYSTEM_PROPERTIES_STRING)

                self.logger.info("Create system.{}.".format(properties_file))
            except Exception as e:
                self.logger.error("can not create {}.".format(e))

        if os.path.exists(tmp_properties_file):
            try:
                shutil.move(tmp_properties_file, properties_file)
                self.logger.info("rename {} to {}".format(tmp_properties_file, properties_file))
            except Exception as e:
                self.logger.error("Failed to rename file: {}".format(e))

        if os.path.exists(properties_file) and not os.path.exists(tmp_properties_file):
            try:
                shutil.move(tmp_properties_file, properties_file)
                self.logger.info("rename {} to {}".format(tmp_properties_file, properties_file))
            except Exception as e:
                self.logger.error("Failed to rename file: {}".format(e))

        if os.path.exists(properties_file) and not os.path.exists(tmp_properties_file):
            try:
                with open(properties_file, "r") as f:
                    for k, v in properties.items():
                        system_properties.setProperty(k, v)
            except Exception as e:
                self.logger.error("Failed to read file: {}".format(e))

        if timestamp_precision != properties.getProperty(TIMESTAMP_PRECISION_STRING):
            print_error_log_and_exit(TIMESTAMP_PRECISION_STRING)

    def upgradePropertiesFile(self):
        try:
            with open(tmp_properties_file, "w") as f:
                for k, v in system_properties.items():
                    if not properties.contains_key(k):
                        properties.setProperty(k, v)
                    properties.store(f, SYSTEM_PROPERTIES_STRING)
        except Exception as e:
            self.logger.error("Failed to upgrade file: {}".format(e))

    def checkProperties(self):
        for entry in system_properties.items():
            if not properties.contains_key(entry[0]):
                self.upgradePropertiesFile()
                self.logger.info("repair system.{}.".format(entry[0]))

    def print_error_log_and_exit(self, property):
        self.logger.error(
            "Wrong {}, please set as:  ! Current is: {}.".format(property, properties.getProperty(property))
        )
        exit(-1)

    def checkUnClosedTsFileV2(self):
        if os.path.exists(WAL_DIR) and os.listdir(WAL_DIR).length != 0:
            self.logger.error(
                "WAL detected, please stop insertion, then run 'flush' on IoTDB {} before upgrading to {}".format(properties.getProperty(IOTDB_VERSION_STRING), IOTDBConstant.VERSION)
            )
            exit(-1)

        for folder in DirectoryManager.getInstance().getAllSequenceFileFolders():
            if not os.path.exists(folder):
                continue
            for storage_group in os.listdir(folder):
                if not os.path.isdir(os.path.join(folder, storage_group)):
                    continue

    def deleteMergingTsFiles(self, tsfiles, resources):
        resources_set = set()
        for resource in resources:
            resources_set.add(resource.name)

        old_tsfile_array = []
        for tsfile in tsfiles:
            if not resources_set.contains(tsfile.name + TsFileResource.RESOURCE_SUFFIX):
                try:
                    self.logger.info("Delete merging {}.".format(tsfile))
                    os.remove(os.path.join(folder, tsfile.name))
                except Exception as e:
                    self.logger.error("Failed to delete file: {}".format(e))

    def moveTsFileV2(self):
        for folder in DirectoryManager.getInstance().getAllSequenceFileFolders():
            if not os.path.exists(folder):
                continue
            for storage_group in os.listdir(folder):
                if not os.path.isdir(os.path.join(folder, storage_group)):
                    continue

    def moveVersionFile(self):
        sg_dir = os.path.join(IoTDBConfigCheck.SCHEMA_DIR, "storage_groups")
        if os.path.exists(sg_dir):
            for sg in os.listdir(sg_dir):
                if not os.path.isdir(os.path.join(sg_dir, sg)):
                    continue
