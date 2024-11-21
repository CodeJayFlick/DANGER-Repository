Here is the translation of the Java code into Python:

```Python
import os
from typing import List

class HelpScreenShotReportGenerator:
    ITEMS_PER_PAGE = 25
    PNG_EXT = ".png"

    def __init__(self):
        pass

    @staticmethod
    def main(args: List[str]) -> None:
        if len(args) != 2:
            raise Exception("Expecting 2 args: <output file path> <image filepath[,image filepath,...]>")

        output_file_path = args[0]
        System.out.println(f"Using file path: {output_file_path}")

        images = args[1].strip()
        if not images:
            raise Exception("No image files provided!")

        print(f"Processing image files: {images}")

        tokenizer = StringTokenizer(images, ",")
        list_ = []
        while tokenizer.hasMoreTokens():
            list_.append(tokenizer.nextToken())

        generator = HelpScreenShotReportGenerator()
        generator.generate_report(output_file_path, list_)

    def generate_report(self, file_path: str, list_: List[str]) -> None:
        parent_path = os.path.dirname(file_path)
        base_filename = os.path.basename(file_path).split('.')[0]

        n = len(list_)
        page_count = -(-n // self.ITEMS_PER_PAGE)  # Calculate the ceiling of division
        if n % self.ITEMS_PER_PAGE != 0:
            page_count += 1

        for i in range(page_count):
            file_name_no_extension = f"{base_filename}{i}" if i > 0 else base_filename
            file_path = os.path.join(parent_path, f"{file_name_no_extension}.html")
            print(f"Creating output file: {file_path}")

            with open(file_path, 'w') as writer:
                self.write_file(base_filename, writer, i, page_count, list_)

    def write_file(self, filename_no_extension: str, writer: object, page_number: int, page_count: int, list_: List[str]) -> None:
        writer.write("<HTML>\n")
        writer.write("<HEAD>\n")
        self.create_style_sheet(writer)
        writer.write("</HEAD>\n")
        writer.write("<BODY>\n")
        writer.write("<H1>Ghidra Help Screen Shots</H1>\n")

        start = page_number * self.ITEMS_PER_PAGE
        if start > 0:
            start += 1

        n = min(self.ITEMS_PER_PAGE, len(list_) - start)
        end = start + n
        for i in range(start, end):
            new_file_path = list_[i]
            original_extension = new_file_path.index(self.PNG_EXT)
            length = original_extension + self.PNG_EXT.length()
            old_file_path = new_file_path[:length]

            writer.write("     <TR>\n")
            writer.write("         <TD>\n")
            writer.write(f"             <IMG SRC=\"{old_file_path}\" ALT=\"{old_file_path}.html\"><BR>\n")
            writer.write("             <CENTER><FONT COLOR=\"GRAY\">{}</FONT></CENTER>\n".format(old_file_path))
            writer.write("         </TD>\n")
            writer.write("         <TD>\n")
            writer.write(f"             <IMG SRC=\"{new_file_path}\" ALT=\"{new_file_path}.html\"><BR>\n")
            writer.write("             <CENTER><FONT COLOR=\"GRAY\">{}</FONT></CENTER>\n".format(new_file_path))
            writer.write("         </TD>\n")
            writer.write("     </TR>\n")

        writer.write("</TABLE>\n")
        writer.write("</P>")

        self.write_footer(filename_no_extension, writer, page_count)

    def write_header(self, writer: object) -> None:
        writer.write("<HTML>\n")
        writer.write("<HEAD>\n")
        self.create_style_sheet(writer)
        writer.write("</HEAD>\n")
        writer.write("<BODY>\n")
        writer.write("<H1>Ghidra Help Screen Shots</H1>\n")

    def write_footer(self, filename_no_extension: str, writer: object, page_count: int) -> None:
        writer.write("<BR>\n")
        writer.write("<BR>\n")
        writer.write("<P>\n")
        writer.write("<CENTER>\n")

        for i in range(page_count):
            if i == 0:
                writer.write(f"<A HREF=\"{filename_no_extension}.html\">{(i + 1)}</A>\n")
            else:
                writer.write(f"<A HREF=\"{filename_no_extension}{i}.html\">{(i + 1)}</A>\n")

        writer.write("</CENTER>\n")
        writer.write("</P>\n")

        writer.write("</BODY>\n")
        writer.write("</HTML>\n")

    def create_style_sheet(self, writer: object) -> None:
        writer.write("<style>\n")
        writer.write("<!--\n")

        writer.write("body { font-family: arial; font-size: 22pt }\n")
        writer.write("h1 { color: #000080; font-family: times new roman; font-size: 28pt; font-weight: bold; text-align: center }\n")
        writer.write("h2 { color: #984c4c; font-family: times new roman; font-size: 14pt; font-weight: bold }\n")
        writer.write("h3 { color: #0000ff; font-family: times new roman; font-size: 14pt; font-weight: bold; margin-left: .5in }\n")
        writer.write("table { margin-left: 1in; min-width: 20em; width: 95%; background-color: #EEEEFF }\n")
        writer.write("th { text-align: center }\n")
        writer.write("td { text-align: center; padding: 20px }\n")

        writer.write("-->\n")
        writer.write("</style>\n")


if __name__ == "__main__":
    HelpScreenShotReportGenerator.main(sys.argv[1:])
```

Please note that Python does not have a direct equivalent to Java's `System.out.println()`. Instead, you can use the built-in `print()` function.