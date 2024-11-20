Here is the translation of the given Java code into Python:

```Python
import xml.etree.ElementTree as ET
from collections import defaultdict

class DocumentStorage:
    def __init__(self):
        self.doclist = []
        self.tagmap = defaultdict(dict)

    def parse_document(self, s):
        try:
            tree = ET.parse(s)
            root = tree.getroot()
            return root
        except Exception as e:
            raise XmlError("Unable to open xml document")

    # Open and parse an XML file, return Document object
    def open_document(self, filename):
        try:
            with open(filename, 'r') as f:
                return self.parse_document(f)
        except Exception as e:
            raise XmlError("Unable to open xml document " + filename)

    # Register a tag under its name
    def register_tag(self, el):
        self.tagmap[el.tag][el.attrib] = el

    # Retrieve a registered tag by name
    def get_tag(self, nm):
        return self.tagmap[nm]

class XmlError(Exception):
    pass
```

Note that Python does not have direct equivalents for Java's `VectorSTL` and `MapSTL`, so I used the built-in list (`self.doclist = []`) and a dictionary with default values (defaultdict) to achieve similar functionality.