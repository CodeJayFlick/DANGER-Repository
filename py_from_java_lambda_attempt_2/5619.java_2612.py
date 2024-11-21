Here is the translation of the given Java code into Python:

```Python
import xml.etree.ElementTree as ET

class CommentsXmlMgr:
    def __init__(self, program, log):
        self.program = program
        self.log = log
        self.factory = program.get_address_factory()
        self.listing = program.get_listing()

    def read(self, parser, monitor):
        while True:
            if monitor.is_cancelled():
                raise CancelledException()
            element = next(parser)
            if not element.tag == "COMMENT":
                break
            if element.text is None or len(element.text) == 0:
                continue
            self.process_comment(element)

    def write(self, writer, set, monitor):
        monitor.set_message("Writing COMMENTS...")
        if set is None:
            set = self.program.get_memory()
        writer.start_element("COMMENTS")
        for cu in self.listing.get_code_unit_iterator(CodeUnit.COMMENT_PROPERTY, set, True):
            for i, comment_type in enumerate(CommentTypes.get_types()):
                comments = cu.get_comment(comment_type)
                if comments is not None:
                    self.write_comment(writer, cu.min_address(), CommentTags[i], comments)
        writer.end_element("COMMENTS")

    def process_comment(self, element):
        addr_str = element.attrib["ADDRESS"]
        try:
            addr = XmlProgramUtilities.parse_address(self.factory, addr_str)
            if addr is None:
                raise AddressFormatException(f"Incompatible comment address: {addr_str}")
            type_str = element.attrib["TYPE"]
            comment_type = self.get_comment_type(type_str)
            if comment_type < 0:
                self.log.append_msg(f"Unknown comment type: {type_str}")
                return
            comments = element.text
            cu = self.listing.get_code_unit_at(addr)
            if cu is not None:
                curr_cmt = cu.get_comment(comment_type)
                if curr_cmt is None or len(curr_cmt) == 0:
                    cu.set_comment(comment_type, comments)
                else:
                    log.append_msg(f"Merged {type_str} comment at {addr}")
                    cu.set_comment(comment_type, f"{curr_cmt}\n\n{comments}")
        except Exception as e:
            self.log.append_exception(e)

    def write_comment(self, writer, addr, type_str, comments):
        attrs = {"ADDRESS": str(addr), "TYPE": type_str}
        writer.write_element("COMMENT", attrs, comments)

    def get_comment_type(self, type_str):
        for i, tag in enumerate(CommentTags):
            if tag == type_str:
                return CommentTypes[i]
        return -1  # unknown comment

class CancelledException(Exception): pass
```

Note that this translation is not a direct conversion from Java to Python. It's more of an interpretation of the code into Python, considering best practices and idioms specific to each language.

Here are some key differences:

- In Python, we use `try/except` blocks for error handling instead of exceptions.
- We don't need explicit type declarations in Python as it is dynamically typed.
- The `get_comment_type()` method now iterates over the list using a simple loop and returns -1 if no match found.