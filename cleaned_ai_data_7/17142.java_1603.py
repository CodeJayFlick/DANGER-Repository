import os
import logging
from typing import Dict, List

class MLogUpgrader:
    def __init__(self,
                 schema_dir: str,
                 old_file_name: str,
                 new_file_name: str,
                 is_snapshot: bool):
        self.schema_dir = schema_dir
        self.old_file_name = old_file_name
        self.new_file_name = new_file_name
        self.is_snapshot = is_snapshot

    @staticmethod
    def upgrade_mlog() -> None:
        schema_dir = IoTDBDescriptor.get_instance().get_config().get_schema_dir()
        m_log_upgrader = MLogUpgrader(
            schema_dir, MetadataConstant.METADATA_TXT_LOG,
            MetadataConstant.METADATA_LOG, False)
        m_log_upgrader.upgrade_txt_to_bin()
        m_tree_snapshot_upgrader = MLogUpgrader(
            schema_dir, MetadataConstant.MTREE_TXT_SNAPSHOT,
            MetadataConstant.MTREE_SNAPSHOT, True)
        m_tree_snapshot_upgrader.upgrade_txt_to_bin()

    def upgrade_txt_to_bin(self) -> None:
        log_file_path = os.path.join(self.schema_dir, self.new_file_name)
        tmp_log_file_path = f"{log_file_path}.tmp"
        old_log_file_path = os.path.join(self.schema_dir, self.old_file_name)
        tmp_old_log_file_path = f"{old_log_file_path}.tmp"

        if os.path.exists(old_log_file_path) or os.path.exists(tmp_old_log_file_path):
            if tmp_old_log_file_path and not os.path.exists(log_file_path):
                try:
                    os.rename(tmp_old_log_file_path, old_log_file_path)
                except Exception as e:
                    logging.error(f"Failed to rename file: {e}")

            m_log_writer = MLogWriter(self.schema_dir, self.new_file_name + ".tmp")
            m_log_txt_reader = MLogTxtReader(self.schema_dir, self.old_file_name)
            tag_log_file = TagLogFile(
                IoTDBDescriptor.get_instance().get_config().get_schema_dir(),
                MetadataConstant.TAG_LOG)

            while m_log_txt_reader.has_next():
                cmd = m_log_txt_reader.next()
                if not cmd:
                    break
                try:
                    self.operation(cmd, self.is_snapshot)
                except (MetadataException, Exception) as e:
                    logging.error(f"Failed to upgrade command: {cmd}, error: {e}")

            # release the .bin.tmp file handler
            m_log_writer.close()
            try:
                os.rename(tmp_log_file_path, log_file_path)
            except Exception as e:
                logging.error(f"Failed to rename file: {e}")

        elif not os.path.exists(log_file_path) and os.path.exists(tmp_log_file_path):
            # if both .bin and .bin.tmp do not exist, nothing to do
            pass

        else:
            try:
                os.remove(tmp_old_log_file_path)
            except Exception as e:
                logging.error(f"Failed to delete file: {e}")

    def operation(self, cmd: str, is_snapshot: bool) -> None:
        if not is_snapshot:
            self.operation(cmd)

        plan = convert_from_string(cmd)
        if plan:
            m_log_writer.put_log(plan)

    @staticmethod
    def create_timeseries_plan(
            partial_path: PartialPath,
            ts_data_type: TSDataType,
            tse_encoding: TSEncoding,
            compression_type: CompressionType,
            props: Dict[str, str],
            tags: Dict[str, str],
            attributes: Dict[str, str],
            alias: str) -> CreateTimeSeriesPlan:
        # implementation
        pass

    def operation(self, cmd: str) -> None:
        args = cmd.split(",", -1)
        if len(args) > 8:
            tmp_args = [args[0]] + [""] * (len(args) - 7) + list(args[2:])
            for i in range(1, len(tmp_args)):
                tmp_args[i] = f"{tmp_args[i-1]},"
            args = tmp_args

        props = {}
        if not args[5].strip():
            key_values = [kv.split("=") for kv in args[5].split("&")]
            for kv in key_values:
                props[kv[0]] = kv[1]

        alias = None
        if not args[6].strip():
            alias = args[6]

        offset = -1
        tags = {}
        attributes = {}
        if not args[7].strip():
            tag_attribute_pair = self.tag_log_file.read(
                IoTDBDescriptor.get_instance().get_config().get_tag_attribute_total_size(), int(args[7]))
            tags = tag_attribute_pair.left
            attributes = tag_attribute_pair.right

        plan = CreateTimeSeriesPlan(
            partial_path=PartialPath(args[1]),
            ts_data_type=TSDataType.deserialize((byte)Short.parseShort(args[2])),
            tse_encoding=TSEncoding.deserialize((byte)Short.parseShort(args[3])),
            compression_type=CompressionType.deserialize((byte)Short.parseShort(args[4])),
            props=props,
            tags=tags,
            attributes=attributes,
            alias=alias)

        plan.set_tag_offset(int(offset))
        self.m_log_writer.create_timeseries(plan)
