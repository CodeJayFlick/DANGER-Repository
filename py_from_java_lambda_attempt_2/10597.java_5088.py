Here is the translation of the Java code into Python:

```Python
import xml.etree.ElementTree as ET
from io import StringIO
from collections import deque, defaultdict


class XmlElement:
    def __init__(self, name):
        self.name = name
        self.attributes = {}
        self.text = ""


class NonThreadedXmlPullParserImpl:
    def __init__(self, file=None, err_handler=None, validate=False):
        if file is not None:
            try:
                with open(file) as f:
                    self.fill_queue(f.read(), file.name, err_handler, validate)
            except Exception as e:
                raise SAXException(e)

    def fill_queue(self, input_string, name, err_handler, validate):
        content_handler = DefaultContentHandler(err_handler)
        sax_parser_factory = ET.XMLParser()
        sax_parser = sax_parser_factory.parse(StringIO(input_string), content_handler)
        return

    @property
    def queue(self):
        if not hasattr(self, '_queue'):
            self._queue = deque()
        return self._queue


class DefaultContentHandler:
    def __init__(self, err_handler=None):
        self.err_handler = err_handler
        self.text_buf = ""

    def characters(self, ch, start, length):
        self.text_buf += ch[start:start+length]

    def processing_instruction(self, target, data):
        if not hasattr(self, '_processing_instructions'):
            self._processing_instructions = defaultdict(dict)
        map = self._processing_instructions[target.upper()]
        tokenizer = iter(data.split())
        for token in tokenizer:
            attr_value_pair = token
            ix = attr_value_pair.find('=')
            if ix < 1 or ix == len(attr_value_pair) - 1:
                return
            attr = attr_value_pair[:ix].strip()
            value = attr_value_pair[ix+1:].strip().replace('"', '')
            map[attr.upper()] = value

    def start_element(self, namespace_uri, local_name, qname, atts):
        self.text_buf = ""
        level += 1
        queue.append(XmlElement(qname))

    def end_element(self, namespace_uri, local_name, qname):
        if really_create_noncompliant_deprecated:
            qname = qname.upper()
        queue.append(XmlElement(False, True, qname, level, None, self.text_buf, locator.get_column_number(), locator.get_line_number()))
        text_buf = ""
        --level


class XmlPullParserImpl(NonThreadedXmlPullParserImpl):
    def __init__(self, file=None, err_handler=None, validate=False):
        super().__init__(file=file, err_handler=err_handler, validate=validate)

    @property
    def name(self):
        return self._name

    def get_processing_instruction(self, pi_name, attribute):
        map = self._processing_instructions.get(pi_name.upper())
        if map is None:
            return None
        return map[attribute.upper()]

    def hasNext(self):
        return not queue.empty()

    def next(self):
        if has_next():
            return queue.popleft()
        return None

    def peek(self):
        if has_next():
            return queue[0]
        return None


class XmlElementImpl(XmlElement):
    def __init__(self, is_start_element, is_end_element, name, level, attributes=None, text="", line_number=1, column_number=1):
        super().__init__(name)
        self.is_start_element = is_start_element
        self.is_end_element = is_end_element
        self.level = level
        if attributes:
            for key in attributes.keys():
                self.attributes[key] = attributes[key]
        self.text = text
```

Please note that this translation may not be perfect, as the original Java code has some complex logic and error handling.