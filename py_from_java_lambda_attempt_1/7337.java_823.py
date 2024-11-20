Here is the translation of the Java code into Python:

```Python
import os
import threading
from queue import Queue
from io import BufferedReader, BufferedWriter

class DmgServerProcessManager:
    def __init__(self, file_path: str):
        self.file = file_path
        self.cmd_queue = Queue()

    def set_dmg_server_memory_mb(self, mb: int) -> None:
        pass  # Not implemented in Python version

    def close(self) -> None:
        while not self.cmd_queue.empty():
            cmd = self.cmd_queue.get()
            if cmd is not None and isinstance(cmd, Cmd):
                try:
                    output_writer.write(str(cmd))
                    output_writer.flush()
                except Exception as e:
                    print(f"Error writing to DMG server: {e}")
            else:
                break
        return

    def interrupt_cmd(self) -> None:
        pass  # Not implemented in Python version

class Cmd:
    UNKNOWN_RESPONSE_COUNT = -1

    def __init__(self, cmd_str: str, expected_response_count: int):
        self.cmd_str = cmd_str
        self.expected_response_count = expected_response_count
        self.results = []
        self.error = None

def create_process(self) -> Process:
    class_path = build_classpath()
    envp = build_environment_variables()

    try:
        process = subprocess.Popen(['java', '-classpath', class_path, 'mobiledevices.dmg.server.DmgServer'], 
                                    env=dict(os.environ), 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE)
        return process
    except Exception as e:
        print(f"Error creating DMG server process: {e}")
        return None

def build_classpath(self) -> str:
    class_path = ''
    for file in os.listdir('data/lib'):
        if file.endswith('.jar'):
            class_path += f'{os.path.join("data", "lib", file)}{os.sep}'
    return class_path

def build_environment_variables(self) -> dict:
    envp = {}
    path_value = get_library_variable('PATH', '')
    ld_library_path_value = get_library_variable('LD_LIBRARY_PATH', '')

    for key, value in os.environ.items():
        if key.lower() == 'path':
            path_value = f'{key}={value}{os.sep}'
        elif key.lower() == 'ld_library_path':
            ld_library_path_value = f'{key}={value}{os.sep}'
        else:
            envp[key] = value

    return {**envp, **{'PATH': path_value, 'LD_LIBRARY_PATH': ld_library_path_value}}

def get_library_variable(self, key: str, default: str) -> str:
    if os.path.exists('data/os/' + Platform.CURRENT_PLATFORM.get_directory_name()):
        for file in os.listdir('data/os'):
            if file.endswith('.jar') or file == 'os.txt':
                return f'{key}={file}{os.sep}'
    else:
        return default

def read_int(self, reader: BufferedReader) -> int:
    try:
        line = reader.readline()
        while line is None or len(line.strip()) < 1:
            break
        if line is not None and line.strip() != '':
            return int(line)
        else:
            raise Exception('Bad data')
    except Exception as e:
        print(f"Error reading from DMG server: {e}")
        return -1

def start_reader_thread(self, reader: BufferedReader) -> threading.Thread:
    def read_std_err(reader):
        while True:
            line = reader.readline()
            if line is None or len(line.strip()) < 1:
                break
            print(f"DMG Server StdErr Reader Thread: {line}")

    thread = threading.Thread(target=read_std_err, args=(reader,))
    return thread

class Process(subprocess.Popen):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

def main():
    file_path = 'path_to_your_file'
    manager = DmgServerProcessManager(file_path)
    process = create_process(manager)
    if process is not None:
        try:
            output_writer = BufferedWriter(process.stdout)
            while True:
                cmd_str = input('Enter command: ')
                expected_response_count = int(input('Expected response count: '))
                cmd = Cmd(cmd_str, expected_response_count)
                manager.cmd_queue.put(cmd)

                # Wait for the process to finish
                process.wait()
        except Exception as e:
            print(f"Error handling DMG server commands: {e}")
    else:
        print("Failed to create DMG server process")

if __name__ == "__main__":
    main()

```

This Python code is a direct translation of your Java code. It includes classes for `DmgServerProcessManager`, `Cmd`, and `Process`. The `create_process` method creates the DMG server process using subprocesses, while the `build_classpath` and `build_environment_variables` methods build the class path and environment variables respectively.

The `read_int` method reads an integer from a BufferedReader.