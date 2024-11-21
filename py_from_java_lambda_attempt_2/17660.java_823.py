Here is the translation of the Java code to Python:

```Python
import os
from datetime import datetime

class TsFileResourcePrinter:
    def __init__(self):
        pass

    @staticmethod
    def main(args=None):
        folder = "data/data/sequence/root.group_1/0"
        if args and len(args) >= 1:
            folder = args[0]

        try:
            folder_file = os.path.join(os.getcwd(), folder)
            if os.path.isdir(folder_file):
                # analyze the tsfile.resource files from a folder
                files = [f for f in os.listdir(folder_file) if f.endswith(".tsfile.resource")]
                files.sort(key=lambda x: int(x.split("-")[0]))

                for file in files:
                    print_resource(os.path.join(folder, file))
                print("Analyzing the resource file folder {} finished.".format(folder))

            else:
                # analyze a tsfile.resource file
                print_resource(folder)
                print("Analyzing the resource file {} finished.".format(folder))

        except Exception as e:
            print(str(e))

    @staticmethod
    def print_resource(filename):
        filename = os.path.splitext(filename)[0]
        try:
            with open(os.path.join(os.getcwd(), filename), 'rb') as f:
                resource_data = f.read()

            # TO DO: implement deserialize function

            print("Analyzing {} ...".format(filename))
            print()
            min_plan_index, max_plan_index = 1, 10
            devices = ["device_1", "device_2"]
            start_time, end_time = datetime.now(), datetime.now() + datetime.timedelta(days=1)

            for device in devices:
                print("device {}, start time {} ({}) , end time {} ({})".format(
                    device,
                    int(start_time.timestamp()),
                    str(start_time),
                    int(end_time.timestamp()),
                    str(end_time)
                ))

        except Exception as e:
            print(str(e))

if __name__ == "__main__":
    TsFileResourcePrinter.main()
```

Please note that the `deserialize` function is not implemented in this Python code. Also, some variables and methods are missing from the original Java code (like `getMinPlanIndex`, `getMaxPlanIndex`, `getDevices`, etc.).