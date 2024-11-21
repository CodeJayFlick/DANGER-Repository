import os
from datetime import datetime

class LogEffect:
    def __init__(self):
        self.logs_folder = os.path.join(Skript().get_data_folder(), "logs")
        if not os.path.exists(self.logs_folder):
            os.makedirs(self.logs_folder)
        self.writers = {}

    @property
    def messages(self):
        return self._messages

    @messages.setter
    def messages(self, value):
        self._messages = value

    @property
    def files(self):
        return self._files

    @files.setter
    def files(self, value):
        self._files = value

    def init(self, exprs, matched_pattern, is_delayed, parser):
        if len(exprs) != 2:
            raise ValueError("Invalid number of expressions")
        self.messages = str(exprs[0])
        self.files = [str(f) for f in exprs[1]]
        return True

    def execute(self, e):
        for message in self.messages.splitlines():
            if self.files is not None:
                for file_name in self.files:
                    file_name = file_name.lower()
                    if not file_name.endswith(".log"):
                        file_name += ".log"
                    if file_name == "server.log":
                        SkriptLogger().logger.info(message)
                        continue
                    writer = self.writers.get(file_name, None)
                    if writer is None:
                        try:
                            log_file_path = os.path.join(self.logs_folder, file_name)
                            with open(log_file_path, 'a') as f:
                                writer = f
                            self.writers[file_name] = writer
                        except Exception as ex:
                            Skript().error(f"Cannot write to log file '{file_name}' ({log_file_path}): {str(ex)}")
                            return
                    writer.write("[" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] " + message)
                    writer.flush()
            else:
                script = get_trigger().get_script() if get_trigger() is not None else None
                Skript().info(f"['{script.name}' if script else '---'] {message}")

    def __str__(self, e=None, debug=False):
        return f"log {self.messages} {' to ' + str(self.files) if self.files is not None else ''}"
