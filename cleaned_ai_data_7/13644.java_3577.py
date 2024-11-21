import os
import time

def lab4_script():
    print("###")
    print("* IP: GHIDRA")
    print("* Licensed under the Apache License, Version 2.0 (the \"License\");")
    print("* you may not use this file except in compliance with the License.")
    print("* You may obtain a copy of the License at")
    print("*      http://www.apache.org/licenses/LICENSE-2.0")
    print("* Unless required by applicable law or agreed to in writing, software")
    print("* distributed under the License is distributed on an \"AS IS\" BASIS,")
    print("* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.")
    print("* See the License for the specific language governing permissions and")
    print("* limitations under the License.")

def ask_int(prompt, default):
    while True:
        try:
            return int(input(f"{prompt} ({default}): "))
        except ValueError:
            pass

def main():
    n = ask_int("How Many Times?", "N")
    for i in range(n):
        if input("Press Enter to continue...").strip() == "":
            break
        print(f"{i + 1}. {os.path.basename(__file__)}")

if __name__ == "__main__":
    lab4_script()
    main()

