import sys
import threading
from io import BufferedReader, InputStreamReader

class DebuggerConsole(threading.Thread):
    def __init__(self, model):
        self.model = model
        self.reader = BufferedReader(InputStreamReader(sys.stdin))
        self.interpreter = None
        self.closed = False

    def run(self):
        while not self.closed:
            line = self.reader.readline()
            if line is None:
                return  # EOF
            if self.interpreter is None:
                print("Have not found interpreter, yet", file=sys.stderr)
                continue
            try:
                result = self.interpreter.execute(line.decode('utf-8'))
                result.add_done_callback(lambda x: print(f"Command finished") if x else print(f"Command error: {x.exception().message}", file=sys.stderr))
            except Exception as e:
                print("IOException on console:", str(e), file=sys.stderr)

    def close(self):
        self.model.remove_model_listener(self)
        self.closed = True
        self.interrupt()

if __name__ == '__main__':
    # Example usage: create a DebuggerConsole instance and start it
    model = ...  # assume you have a DebuggerObjectModel instance here
    console = DebuggerConsole(model)
    console.start()
