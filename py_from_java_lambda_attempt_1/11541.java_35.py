Here is the translation of the Java code into Python:

```Python
class UseropSymbol:
    def __init__(self):
        self.index = None  # Unique id for this userop

    @property
    def index(self):
        return self._index

    @index.setter
    def index(self, value):
        self._index = value

    def restore_xml(self, parser, sleigh_language):
        el = parser.get_start_tag("userop")
        if "index" in el.attrib:
            self.index = int(el.attrib["index"])
```

Note that Python does not have direct equivalent of Java's `@Override` annotation. Also, the `XmlPullParser`, `XmlElement`, and `SpecXmlUtils` classes are specific to Java and do not exist in Python.