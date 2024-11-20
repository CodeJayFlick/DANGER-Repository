Here is the equivalent Python script:

```Python
import time
from threading import Thread

class ProgressExampleScript:
    def run(self):
        for i in range(10):
            print(f"Working on {i}")
            time.sleep(1)
            yield

def main():
    progress_example_script = ProgressExampleScript()
    progress_example_script.run()

if __name__ == "__main__":
    main()
```

This Python script does not have direct equivalent to the `GhidraScript` and its methods in Java. The provided code seems to be related to a GUI application, which is not directly translatable to pure Python. However, I've written an example of how you could simulate progress reporting using generators (which can be used with threads) or even just printing messages to the console.

Please note that this script does not have any direct equivalent to `GhidraScript` and its methods in Java.