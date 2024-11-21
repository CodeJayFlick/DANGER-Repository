import os
import sys
from io import StringIO
from typing import List

class CommonUtils:
    CPUS = os.cpu_count()

    MAX_EXECUTOR_POOL_SIZE = max(100, CPUS * 5)

    def __init__(self):
        pass

    @staticmethod
    def get_jdk_version() -> int:
        java_version = sys.version_info.major if sys.version_info.minor == 0 else sys.version_info.major + '.' + str(sys.version_info.minor)
        return int(java_version.split('.')[1])

    @staticmethod
    def get_usable_space(dir: str) -> long:
        dir_path = os.path.join(os.getcwd(), dir)
        try:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            return os.statvfs(dir_path).f_frsize * (os.statvfs(dir_path).f_bavail + os.statvfs(dir_path).f_free_blocks * os.statvfs(dir_path).f_frsize)
        except Exception as e:
            print(f"Error: {e}")
            return 0

    @staticmethod
    def has_space(dir: str) -> bool:
        usable_space = CommonUtils.get_usable_space(dir)
        if usable_space > 0:
            return True
        else:
            return False

    @staticmethod
    def get_occupied_space(folder_path: str) -> long:
        try:
            total_size = 0
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    filepath = os.path.join(root, file)
                    total_size += os.path.getsize(filepath)
            return total_size
        except Exception as e:
            print(f"Error: {e}")
            return 0

    @staticmethod
    def parse_value(data_type: str, value: str) -> object:
        try:
            if value.lower() == "null":
                return None
            elif data_type == 'BOOLEAN':
                return bool(parse_boolean(value))
            elif data_type in ['INT32', 'INT64']:
                return int(value)
            elif data_type in ['FLOAT', 'DOUBLE']:
                return float(value)
            elif data_type == 'TEXT':
                if value.startswith('"') and value.endswith('"'):
                    return value[1:-1]
                else:
                    return value
        except Exception as e:
            print(f"Error: {e}")
            return None

    @staticmethod
    def parse_boolean(value: str) -> bool:
        try:
            value = value.lower()
            if value in ['false', '0']:
                return False
            elif value in ['true', '1']:
                return True
            else:
                raise Exception("The BOOLEAN should be true/TRUE, false/FALSE or 0/1")
        except Exception as e:
            print(f"Error: {e}")
            return None

    @staticmethod
    def get_cpu_cores() -> int:
        return CommonUtils.CPUS

    @staticmethod
    def get_max_executor_pool_size() -> int:
        return CommonUtils.MAX_EXECUTOR_POOL_SIZE

    @staticmethod
    def run_cli(commands: List, args: list, cli_name: str, cli_description: str) -> int:
        try:
            parser = CliParser(cli_name)
            parser.with_description(cli_description).with_default_command(HelpCommand()).with_commands(commands)

            status = 0
            try:
                parse_result = parser.parse(args)
                if isinstance(parse_result, HelpCommand):
                    print("Help command")
                else:
                    raise Exception(f"Invalid CLI command: {args[0]}")

            except (ArgumentError, ArgumentError) as e:
                bad_use(e)
                status = 1
            except Exception as e:
                err(Throwables.get_root_cause(e))
                status = 2

        return status

    @staticmethod
    def bad_use(e: Exception):
        print(f"node-tool: {e.message}")
        print("See 'node-tool help' or 'node-tool help <command>'.")
        sys.exit(status)

    @staticmethod
    def err(e: Exception):
        print(f"error: {e.message}")
        print("-- StackTrace --")
        print(Throwables.get_stack_trace_string(e))
