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
