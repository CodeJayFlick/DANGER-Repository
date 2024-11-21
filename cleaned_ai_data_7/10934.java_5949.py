import xml.etree.ElementTree as ET
from collections import defaultdict
import os
import sys

class TOCConverter:
    def __init__(self, source_filename, out_filename):
        self.source_filename = source_filename
        self.out_filename = out_filename
        self.url_map = {}
        self.toc_list = []
        self.read_source_toc()
        self.write_java_help_toc()

    def write_toc_map_file(self, file):
        for i in range(len(self.toc_list)):
            target = self.toc_list[i]
            url = self.url_map[target]

            line = f"  <mapID target=\"{target}\" url=\"{url}\">"
            file.write(line + "\n")
        file.write("   <!-- End of Table of Contents help IDs -->\n")

    def read_source_toc(self):
        tree = ET.parse(self.source_filename)
        root = tree.getroot()

        for child in root:
            if child.tag == "tocitem":
                text = child.find(".//text").attrib["value"]
                target = child.find(".//target").attrib["value"]

                self.url_map[target] = url
                self.toc_list.append(target)

    def write_java_help_toc(self):
        with open(self.out_filename, 'w') as file:
            reader = open(self.source_filename, 'r')
            line = None

            while (line := reader.readline()):
                if line.startswith("<tocitem"):
                    item = parse_line(line)
                    endline = ">"

                    if not line.endswith("/>"):
                        endline = " />"
                    line = get_pad_string(line) + "<tocitem text=\"" + item.text + "\">" + endline

                    if item.target:
                        line += f" target=\"{item.target}\""

                elif line.startswith("<!DOCTYPE"):
                    file.write("<!-- This is the JavaHelp Table of Contents file -->\n")
                    file.write(f"<!-- Auto generated on {str(datetime.now())}: Do not edit! -->\n")

                if not line.startswith("// Source"):
                    file.write(line)

            reader.close()
        with open(self.out_filename, 'a') as file:
            self.write_toc_map_file(file)
        print("  TOC conversion is done!")

    def get_pad_string(self, line):
        sb = StringBuffer()

        for i in range(len(line)):
            if line[i] == " ":
                sb.append(' ')
            else:
                break

        return str(sb)

    def parse_line(self, line):
        pos = line.index("<tocitem")
        line = line[pos + len("<tocitem"):]

        st = StringTokenizer(line, "\"")

        text = st.nextToken()
        if not st.hasMoreTokens():
            return TOCItem(text, "")

        target = st.nextToken()

        return TOCItem(text, target)

    def create_temp_toc_file(self):
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        reader = open(self.source_filename, 'r')

        end_line_found = True
        line = None

        while (line := reader.readline()):
            if line.startswith("<!DOCTYPE"):
                if not line.endswith(">"):
                    continue
                end_line_found = False

            if not end_line_found:
                if line.endswith(">"):
                    end_line_found = True
                    continue

            temp_file.write(line)

        temp_file.close()
        return temp_file.name


class TOCItem:
    def __init__(self, text, target):
        self.text = text
        self.target = target.replace('.', '_').replace('#', '_').replace('-', '_')


def main():
    if len(sys.argv) < 2:
        print("Usage: python toc_converter.py [source TOC filename] [out filename]")
        sys.exit(0)

    try:
        conv = TOCConverter(sys.argv[1], sys.argv[2])
        file_name = os.path.basename(sys.argv[2])
        name = "map_" + file_name

        with open(name, 'w') as out_file:
            conv.write_toc_map_file(out_file)
    except Exception as e:
        print(str(e))


if __name__ == "__main__":
    main()
