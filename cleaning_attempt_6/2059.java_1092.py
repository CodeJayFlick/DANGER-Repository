import threading
from typing import List, Map

class JdiModelTargetProcess:
    def __init__(self, vm: any, process: any, is_element: bool):
        self.process = process
        #super().__init__(vm, get_unique_id(process), process, is_element)
        
        input_thread = threading.Thread(target=self.read_stream, args=(process.stdin, 'STDOUT'))
        error_thread = threading.Thread(target=self.read_stream, args=(process.stderr, 'STDERR'))

        input_thread.start()
        error_thread.start()

    def read_stream(self, stream: any, channel: str):
        reader = BufferedReader(InputStreamReader(stream))
        
        try:
            line
            while self.process.is_alive() and (line := reader.readline()):
                print(line)
                self.output(channel, line)
        except Exception as e:
            Msg.debug(self, f"{channel}, reader exiting because {e}")

    def get_display(self) -> str:
        if not self.process:
            return super().get_display()
        
        sb = StringBuilder("Process " + str(self.process.pid))
        sb.append(f" alive={self.process.is_alive()}")
        return sb.toString()

    @staticmethod
    def get_unique_id(process: any):
        return hex(process.pid)

    def output(self, channel: str, out: str) -> None:
        if channel == 'STDOUT':
            self.listeners.fire.console_output(self, channel, out)
        elif channel == 'STDERR':
            self.listeners.fire.console_error(self, channel, out)
        else:
            raise AssertionError()

class BufferedReader:
    def __init__(self, reader):
        self.reader = reader

    def read_line(self) -> str | None:
        return self.reader.readline()
