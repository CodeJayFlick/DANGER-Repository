import os
import xml.etree.ElementTree as ET

class JunitTestScan:
    def __init__(self):
        self.TEST_XML_FILTER = lambda x: "TEST-" in x and ".xml" == x[-4:]

    def write_xml_file(self, file_path):
        class_name = file_path.split("/")[-1].split(".")[0][5:]
        root = ET.Element("testsuite")
        root.set("errors", "0")
        root.set("failures", "1")
        root.set("name", class_name)
        root.set("tests", "1")
        root.set("time", "0")

        test_case = ET.SubElement(root, "testcase")
        test_case.set("name", "UNKNOWN ERROR")
        test_case.set("time", "0")

        error = ET.SubElement(test_case, "error")
        error.set("message", "JVM exited prematurely preventing JUnit from properly reporting test results")
        error.set("type", "System Exit Error")

        tree = ET.ElementTree(root)
        tree.write(file_path)

    def main(self):
        if len(sys.argv) != 2:
            print("Incorrect usage!")
            sys.exit(-1)

        data_dir = os.path.abspath(sys.argv[1])
        if not os.path.isdir(data_dir):
            print(f"{data_dir} is not a valid directory")
            sys.exit(-1)

        files = [f for f in os.listdir(data_dir) if self.TEST_XML_FILTER(os.path.join(data_dir, f))]
        for file_path in files:
            if os.path.getsize(file_path) == 0:
                try:
                    print(f"Found bad test data: {file_path}")
                    self.write_xml_file(file_path)
                except Exception as e:
                    print(f"Failed to fix data file: {file_path}")

if __name__ == "__main__":
    JunitTestScan().main()
