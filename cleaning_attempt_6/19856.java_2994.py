import os
import shutil
from typing import Set

class PatcherTool:
    def __init__(self):
        self.source = None
        self.target = None

    @staticmethod
    def main(args: list) -> None:
        if len(args) < 2:
            print("Usage: python SkriptPatcher.py OLD_JAR [OPTIONS]")
            return
        
        current_file_path = os.path.abspath(__file__)
        old_file_path = args[0]
        patched_file_name = "patched-" + os.path.basename(old_file_path)
        patched_file_path = os.path.join(os.getcwd(), patched_file_name)

        print(f"Patch source: {current_file_path}")
        print(f"Old jar: {old_file_path}")

        shutil.copyfile(old_file_path, patched_file_path)

        options = set()
        for arg in args[1:]:
            if arg.startswith("--"):
                option = arg.lstrip("-").replace("_", "").upper()
                options.add(option)
        
        try:
            with open(current_file_path, 'rb') as current_file, \
                    open(patched_file_path, 'wb') as patched_file:
                new_patcher_tool = PatcherTool()
                new_patcher_tool.patch(options, current_file, patched_file)

            print(f"Successfully patched to {patched_file_name}")
        except Exception as e:
            print(f"Error: {str(e)}")

    def patch(self, options: Set[str], source_file: bytes, target_file: bytes) -> None:
        if not options:
            print("Patched nothing, as requested. For minimal changes, use --security.")
        
        for option in options:
            if option == "SECURITY":
                self.copy("effects.EffMessage", True)
                self.copy("expressions.ExprArgument", True)
                self.copy("expressions.ExprColoured", True)
                self.copy("lang.VariableString", True)
                self.copy("util.chat.BungeeConverter", True)
                self.copy("util.chat.ChatCode", True)
                self.copy("util.chat.ChatMessages", True)
                self.copy("util.chat.SkriptChatCode", True)

            elif option == "MEMORY_LEAK":
                self.copy("SkriptEventHandler", True)
                self.copy("effects.Delay", True)
                self.copy("lang.Trigger", True)
                self.copy("util.AsyncEffect", True)

    def copy(self, class_name: str, overwrite: bool) -> None:
        file_name = f"/ch/njol/skript/{class_name.replace('.', '/')}.class"
        target_file_path = os.path.join(os.getcwd(), file_name)
        
        if not overwrite and os.path.exists(target_file_path):
            print(f"Not patching {class_name}, it already exists.")
            return  # Not safe to patch

        source_file_path = f"{os.path.dirname(__file__)}/{file_name}"
        shutil.copy2(source_file_path, target_file_path)

if __name__ == "__main__":
    PatcherTool.main(sys.argv[1:])
