import os
import logging
from typing import List, Dict

class TsFileAndModSettleTool:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.recover_settle_file_map: Dict[str, int] = {}

    @staticmethod
    def get_instance():
        return tsfile_and_mod_settletool()

    @classmethod
    def main(cls, args):
        old_ts_file_resources: Dict[str, TsFileResource] = {}
        find_files_to_be_recovered()
        for entry in cls.get_instance().recover_settle_file_map.items():
            path = entry[0]
            resource = TsFileResource(os.path.join(path))
            resource.set_closed(True)
            old_ts_file_resources[path] = resource
        ts_files: List[os.PathLike] = check_args(args)
        for file in ts_files:
            if not old_ts_file_resources.get(file.name):
                if os.path.exists(f"{file}{TSFILE_SUFFIX}"):
                    resource = TsFileResource(file)
                    resource.set_closed(True)
                    old_ts_file_resources[file.name] = resource
        print(
            f"Totally find {len(old_ts_file_resources)} tsFiles to be settled, including "
            f"{cls.get_instance().recover_settle_file_map.size()} tsFiles to be recovered."
        )
        settle_ts_files_and_mods(old_ts_file_resources)

    @staticmethod
    def check_args(args):
        file_path = "test.tsfile"
        files: List[os.PathLike] = []
        if not args:
            return None
        for arg in args:
            if arg.endswith(TSFILE_SUFFIX):  # it's a file
                f = os.path.join(arg)
                if not os.path.exists(f):
                    cls.get_instance().logger.warn(
                        f"Cannot find TsFile: {arg}"
                    )
                    continue
                files.append(f)
            else:  # it's a dir
                tmp_files = get_all_files_in_one_dir_by_suffix(arg, TSFILE_SUFFIX)
                files.extend(tmp_files)
        return files

    @staticmethod
    def get_all_files_in_one_dir_by_suffix(dir_path: str, suffix: str) -> List[os.PathLike]:
        dir_ = os.path.join(dir_path)
        if not os.path.isdir(dir_):
            cls.get_instance().logger.warn(f"It's not a directory path: {dir_}")
            return []
        files: List[os.PathLike] = [f for f in os.listdir(dir_) if f.endswith(suffix)]
        return files

    @staticmethod
    def settle_ts_files_and_mods(resources_to_be_settled):
        success_count = 0
        new_ts_file_resources: Dict[str, List[TsFileResource]] = {}
        SettleLog.create_settle_log()
        for entry in resources_to_be_settled.items():
            resource_to_be_settled = entry[1]
            settled_ts_file_resources: List[TsFileResource] = []
            try:
                tsfile_and_mod_settletool = TsFileAndModSettleTool.get_instance()
                print(f"Start settling for tsFile: {resource_to_be_settled.ts_file_path}")
                if tsfile_and_mod_settletool.is_settled_file_generated(resource_to_be_settled):
                    settled_ts_file_resources = find_settled_file(resource_to_be_settled)
                    new_ts_file_resources[resource_to_be_settled.ts_file_name] = settled_ts_file_resources
                else:
                    # Write Settle Log, Status 1
                    SettleLog.write_settle_log(
                        resource_to_be_settled.ts_file_path + "," + str(SettleCheckStatus.BEGIN_SETTLE_FILE)
                    )
                    tsfile_and_mod_settletool.settle_one_ts_file_and_mod(resource_to_be_settled, settled_ts_file_resources)
                    # Write Settle Log, Status 2
                    SettleLog.write_settle_log(
                        resource_to_be_settled.ts_file_path + "," + str(SettleCheckStatus.AFTER_SETTLE_FILE)
                    )
                    new_ts_file_resources[resource_to_be_settled.ts_file_name] = settled_ts_file_resources

                move_new_ts_file(resource_to_be_settled, settled_ts_file_resources)

                # Write Settle Log, Status 3
                SettleLog.write_settle_log(
                    resource_to_be_settled.ts_file_path + "," + str(SettleCheckStatus.SETTLE_SUCCESS)
                )
                print(f"Finish settling successfully for tsFile: {resource_to_be_settled.ts_file_path}")
                success_count += 1

            except Exception as e:
                print(f"Meet error while settling the tsFile: {resource_to_be_settled.ts_file_path}")
                e.print_stacktrace()

        if len(resources_to_be_settled) == success_count:
            SettleLog.close_log_writer()
            print("Finish settling all tsfiles Successfully!")
        else:
            print(
                f"Finish Settling, "
                f"{len(resources_to_be_settled) - success_count} tsFiles meet errors."
            )

    @staticmethod
    def settle_one_ts_file_and_mod(old_ts_file_resource: TsFileResource, settled_resources: List[TsFileResource]) -> None:
        if not old_ts_file_resource.is_closed():
            cls.get_instance().logger.warn(
                f"The tsFile {old_ts_file_resource.ts_file_path} should be sealed when rewriting."
            )
            return
        # if no deletions to this tsfile, then return.
        if not old_ts_file_resource.mod_file.exists():
            return

    @staticmethod
    def find_files_to_be_recovered() -> None:
        settle_log = SettleLog.get_settle_log_path()
        try:
            with open(settle_log) as f:
                for line in f.readlines():
                    old_file_path, _ = line.split(",")
                    if int(_) == SettleCheckStatus.SETTLE_SUCCESS.value:
                        cls.get_instance().recover_settle_file_map.pop(old_file_path)
                    else:
                        cls.get_instance().recover_settle_file_map[old_file_path] = _
        except Exception as e:
            cls.get_instance().logger.error(f"Meet error when reading settle log, log path: {settle_log}", e)

    @staticmethod
    def is_settled_file_generated(old_ts_file_resource) -> bool:
        old_file_path = old_ts_file_resource.ts_file_path
        return old_file_path in cls.get_instance().recover_settle_file_map and \
               cls.get_instance().recover_settle_file_map[old_file_path] == SettleCheckStatus.AFTER_SETTLE_FILE.value

    @staticmethod
    def find_settled_file(resource_to_be_settled) -> List[TsFileResource]:
        settled_ts_file_resources: List[TsFileResource] = []
        settle_log.write_settle_log(
            resource_to_be_settled.ts_file_path + "," + str(SettleCheckStatus.BEGIN_SETTLE_FILE)
        )
        partition_dir = os.path.join(resource_to_be_settled.ts_file_path, "partition")
        if not os.listdir(partition_dir):
            return settled_ts_file_resources
        for file in os.listdir(partition_dir):
            if file.endswith(TSFILE_SUFFIX):
                resource = TsFileResource(os.path.join(partition_dir, file))
                resource.deserialize()
                settled_ts_file_resources.append(resource)
        settle_log.write_settle_log(
            resource_to_be_settled.ts_file_path + "," + str(SettleCheckStatus.AFTER_SETTLE_FILE)
        )
        return settled_ts_file_resources

    @staticmethod
    def move_new_ts_file(old_ts_file_resource, settled_resources) -> None:
        for new_ts_file_resource in settled_resources:
            if not os.path.exists(f"{new_ts_file_resource.ts_file_path}{TSFILE_SUFFIX}"):
                continue
            fs_factory = FSFactoryProducer.get_fs_factory()
            old_ts_file = old_ts_file_resource.ts_file
            is_old_file_existed = old_ts_file.exists()
            old_ts_file.delete()
            for file in settled_resources:
                if not os.path.exists(f"{file.ts_file_path}{TSFILE_SUFFIX}"):
                    continue
                fs_factory.move_file(file.ts_file, old_ts_file)
                new_ts_file_resource.set_file(fs_factory.get_file(old_ts_file.parent, file.ts_file.name))
                try:
                    new_ts_file_resource.serialize()
                except Exception as e:
                    print(f"Error serializing {new_ts_file_resource.ts_file_path}: {e}")
            if not is_old_file_existed and os.path.exists(new_partition_dir):
                os.rmdir(new_partition_dir)

    @staticmethod
    def clear_recover_settle_file_map() -> None:
        cls.get_instance().recover_settle_file_map.clear()

class TsFileResource:
    def __init__(self, path: str):
        self.ts_file_path = path

    def set_closed(self, closed: bool) -> None:
        pass  # implement me!

    @staticmethod
    def get_tsfile_name(path: str) -> str:
        return os.path.basename(path)

class SettleLog:
    @staticmethod
    def create_settle_log() -> None:
        pass  # implement me!

    @staticmethod
    def write_settle_log(line: str) -> None:
        pass  # implement me!

    @staticmethod
    def close_log_writer() -> None:
        pass  # implement me!
