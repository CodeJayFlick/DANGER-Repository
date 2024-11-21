import datetime as dt
from typing import List

class OperationResult:
    STOP_OPER = 0
    CONTINUE_OPER = 1
    NO_OPER = 2


def process_command(s: str, connection) -> bool:
    if s is None or not s.strip():
        return True
    
    cmds = [cmd for cmd in s.split(";") if cmd]
    
    for cmd in cmds:
        result = handle_input_cmd(cmd, connection)
        
        match result:
            case OperationResult.STOP_OPER:
                return False
            case OperationResult.CONTINUE_OPER:
                continue
            case _:
                pass
    
    return True


def set_timestamp_display(special_cmd: str) -> None:
    values = special_cmd.split("=")

    if len(values) != 2:
        print(f"Time display format error, please input like {SET_TIMESTAMP_DISPLAY}={RpcUtils.set_time_format(cmd. split('=')[1])}")
        return

    try:
        time_format = RpcUtils.set_time_format(cmd.split('=')[1])
    except Exception as e:
        print(f"time display format error: {e}")

    print(f"Time display type has set to {values[1].strip()}")


def set_timezone(special_cmd: str, cmd: str) -> None:
    values = special_cmd.split("=")

    if len(values) != 2:
        print(f"Time zone format error, please input like {SET_TIME_ZONE}={cmd. split('=')[1]}")
        return

    try:
        connection.set_time_zone(cmd.split('=')[1].strip())
    except Exception as e:
        print(f"Cannot get time zone from server side because: {e}")

    print(f"Current time zone: {connection.get_time_zone()}")


def import_cmd(special_cmd: str, cmd: str) -> None:
    values = special_cmd.split(" ")

    if len(values) != 2:
        print(
            f"Please input like: import /User/myfile. Note that your file path cannot contain any space character)"
        )
        return

    try:
        ImportCsv.import_from_target_path(host, int(port), username, password, cmd.split(' ')[1], connection.get_time_zone())
    except Exception as e:
        print(f"Cannot get time zone from server side because: {e}")

    print(cmd. split(' ')[1])


def main() -> None:
    host = "127.0.0.1"
    port = 6667
    username = ""
    password = ""

    connection = IoTDBConnection()

    while True:
        s = input("IoTDB> ")
        if process_command(s, connection):
            print(f"Msg: {SUCCESS_MESSAGE}")
        else:
            break

if __name__ == "__main__":
    main()
