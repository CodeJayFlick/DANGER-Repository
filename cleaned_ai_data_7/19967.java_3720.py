import os
from io import StringIO, BytesIO
from typing import Any, Dict, List

class FlatFileStorage:
    def __init__(self, name: str):
        self.name = name
        self.loaded = False
        self.changes_writer = None  # type: Optional[PrintWriter]
        self.changes = AtomicInteger(0)
        self.required_changes_for_resave = 1000

    @property
    def file(self) -> str:
        return f"{self.name}.csv"

    def load_i(self, n: SectionNode) -> bool:
        try:
            with open(self.file, 'r', encoding='utf-8') as r:
                reader = BufferedReader(StringReader(r))
                line_num = 0
                while True:
                    line = reader.readline()
                    if not line:
                        break
                    line_num += 1
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    elif line.startswith('# version:'):
                        try:
                            self.version = Version(line[11:].strip())
                        except Exception as e:
                            pass
                    else:
                        split_line = split_csv(line)
                        if split_line is None or len(split_line) != 3:
                            Skript.error(f"Invalid amount of commas in line {line_num} ('{line}')")
                            continue
                        elif split_line[1] == 'null':
                            Variables.variable_loaded(split_line[0], None, self)
                        else:
                            obj = Classes.deserialize(split_line[1], split_line[2])
                            if obj is not None and isinstance(obj, str) and self.version < Version(2, 1):
                                obj = Utils.replace_chat_styles(obj)
                            Variables.variable_loaded(split_line[0], obj, self)

            return True
        except Exception as e:
            Skript.error(f"An I/O error occurred while loading the variables: {ExceptionUtils.toString(e)}")
            return False

    def all_loaded(self):
        pass  # no transaction support

    def requires_file(self) -> bool:
        return True

    @staticmethod
    def encode(data: bytes) -> str:
        r = [chr((data[i] & 0xF0) >> 4).upper() + chr(data[i] & 0xF).upper() for i in range(len(data))]
        return ''.join(r)

    @staticmethod
    def decode(hex: str) -> bytes:
        r = [(ord(c1) << 4 | ord(c2)) for c1, c2 in zip(hex[::2], hex[1::2])]
        return bytes(r)

    @staticmethod
    def split_csv(line: str) -> List[str]:
        pattern = re.compile("(?<=^|,)\\s*([^\",]*|\"([^\"]|\"\")*\")\\s*(,|$)")
        last_end = 0
        r = []
        while True:
            match = pattern.match(line[last_end:])
            if not match:
                break
            v = match.group(1)
            if v.startswith('"'):
                r.append(v[1:-1].replace('""', '"'))
            else:
                r.append(v.strip())
            last_end = match.end()
        return r

    def save(self, final_save: bool) -> None:
        try:
            with open(self.file, 'w', encoding='utf-8') as f:
                pw = PrintWriter(f)
                pw.println("# === Skript's variable storage ===")
                pw.println("# Please do not modify this file manually!")
                pw.println("#")
                pw.println("# version: " + str(Skript.get_version()))
                pw.println()
                self.save_variables(pw, "", Variables.get_variables())
                pw.close()

            if final_save:
                os.rename(self.file, f"{self.name}.csv.~temp")

        except Exception as e:
            Skript.error(f"Unable to make a final save of the database '{database_name}' (no variables are lost): {ExceptionUtils.toString(e)}")
