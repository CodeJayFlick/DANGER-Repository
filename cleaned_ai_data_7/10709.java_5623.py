import xml.etree.ElementTree as ET
from threading import Thread, Semaphore
from queue import Queue
import time

class TestErrorHandler:
    def __init__(self):
        self.my_exception = None

    def error(self, exception):
        self.my_exception = exception

    def fatalError(self, exception):
        self.my_exception = exception

    def warning(self, exception):
        print("Warning")

class ThreadedXmlPullParserImpl:
    def __init__(self, xml_string, test_name, err_handler, is_parsing=False, max_depth=3):
        self.xml_string = xml_string
        self.test_name = test_name
        self.err_handler = err_handler
        self.is_parsing = is_parsing
        self.max_depth = max_depth

    def start(self, tag):
        # implement XML parsing logic here
        pass

    def next(self):
        # implement XML parsing logic here
        pass

    def end(self, element):
        # implement XML parsing logic here
        pass

    def dispose(self):
        self.is_parsing = False

class XmlPullParser:
    def __init__(self, xml_string, test_name, err_handler, is_parsing=False, max_depth=3):
        self.xml_string = xml_string
        self.test_name = test_name
        self.err_handler = err_handler
        self.is_parsing = is_parsing
        self.max_depth = max_depth

    def start(self, tag):
        # implement XML parsing logic here
        pass

    def next(self):
        # implement XML parsing logic here
        pass

    def end(self, element):
        # implement XML parsing logic here
        pass

class Test:
    def test_xxexml(self):
        xml_string = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
     <!ELEMENT foo ANY>
     <!ENTITY xxe SYSTEM "file://@TEMP_FILE@"">]><foo>&xxe; fizzbizz</foo>"""
        parser = ThreadedXmlPullParserImpl(xml_string.encode(), self.__class__.__name__, TestErrorHandler())
        parser.start("foo")
        xml_element = parser.next()
        assert not xml_element.text.contains(b"foobar")

    def test_good_xml(self):
        xml_string = """<?xml version="1.0" encoding="UTF-8"?>
<doc>
  <project name="foo"/>
</doc>"""
        parser = ThreadedXmlPullParserImpl(xml_string.encode(), self.__class__.__name__, TestErrorHandler())
        parser.start("doc")
        project_xml = parser.next()
        assert project_xml is not None
        assert project_xml.get("name") == "foo"
        parser.end(project_xml)

    def test_good_xml_early_exit(self):
        xml_string = """<?xml version="1.0" encoding="UTF-8"?>
<doc>
  <project name="foo"/>
</doc>"""
        parser = ThreadedXmlPullParserImpl(xml_string.encode(), self.__class__.__name__, TestErrorHandler())
        parser.start("doc")
        project_xml = parser.next()
        assert project_xml is not None
        assert project_xml.get("name") == "foo"
        parser.end(project_xml)

    def test_interrupting_parser_thread_does_not_deadlock_client_thread(self):
        xml_string = """<?xml version="1.0" encoding="UTF-8"?>
<doc>
  <project name="foo"/>
</doc>"""
        parser = ThreadedXmlPullParserImpl(xml_string.encode(), self.__class__.__name__, TestErrorHandler())
        parser.start("doc")
        project_xml = parser.next()
        assert project_xml is not None
        assert project_xml.get("name") == "foo"
        parser.end(project_xml)

    def test_bad_xml(self):
        xml_string = """<?xml version="1.0" encoding="UTF-8"?>
<doc>
  <project name="foo"/><project name="foo"/>
</doc>"""
        err_handler = TestErrorHandler()
        parser = ThreadedXmlPullParserImpl(xml_string.encode(), self.__class__.__name__, err_handler)
        try:
            parser.start("doc")
            assert parser.is_parsing
            while parser.has_next():
                parser.next()
            raise Exception("Expected runtime exception from hasNext()")
        except Exception as e:
            # expected
            pass

    def test_dispose_in_another_thread(self):
        xml_string = """<?xml version="1.0" encoding="UTF-8"?>
<doc>
  <project name="foo"/>
</doc>"""
        parser = ThreadedXmlPullParserImpl(xml_string.encode(), self.__class__.__name__, TestErrorHandler())
        parser.start("doc")
        project_xml = parser.next()
        assert project_xml is not None
        assert project_xml.get("name") == "foo"
        parser.end(project_xml)
        assert parser.is_parsing

    def test_more_jobs_than_threads(self):
        parsers = []
        for i in range(25):
            parsers.append(ThreadedXmlPullParserImpl(b"<?xml version='1.0' encoding='UTF-8'?><doc><project name='foo'/></doc>".encode(), self.__class__.__name__, TestErrorHandler()))
        for parser in parsers:
            parser.dispose()

if __name__ == "__main__":
    test = Test()
    test.test_xxexml()
    test.test_good_xml()
    test.test_good_xml_early_exit()
    test.test_interrupting_parser_thread_does_not_deadlock_client_thread()
    test.test_bad_xml()
    test.test_dispose_in_another_thread()
    test.test_more_jobs_than_threads()

