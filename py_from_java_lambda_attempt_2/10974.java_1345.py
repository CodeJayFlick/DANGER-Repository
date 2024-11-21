Here is the translation of the Java code into Python:

```Python
import unittest
from pathlib import Path
from urllib.parse import URLError

class HelpBuildUtilsTest(unittest.TestCase):

    HELP_TOPIC_PATH = "/some/fake/path/to/help/topics"
    TOPIC_AND_FILENAME = "FooTopic/FooFile.html"
    HTML_FILE_PATH = f"{HELP_TOPIC_PATH}/{TOPIC_AND_FILENAME}"

    def __init__(self):
        super().__init__()

    @unittest.skip
    def test_get_relative_help_path(self):
        relative_string = "help/topics/FooTopic/FooFile.html"
        path = Path(f"/some/fake/path/to/{relative_string}")
        relative = HelpBuildUtils.relativize_with_help_topics(path)
        self.assertEqual(relative_string, str(relative))

    @unittest.skip
    def test_get_relative_help_path_no_help_topic_in_path(self):
        invalid_relative_string = "help/topicz/" + TOPIC_AND_FILENAME
        path = Path(f"/some/fake/path/to/{invalid_relative_string}")
        relative = HelpBuildUtils.relativize_with_help_topics(path)
        self.assertIsNone(relative)

    @unittest.skip
    def test_locate_reference_local_help_system_syntax(self):
        source_file = Path(HTML_FILE_PATH)
        reference = "help/topics/shared/foo.png"
        resolved = HelpBuildUtils.locate_reference(source_file, reference)
        self.assertEqual(resolved, Path(reference))

    @unittest.skip
    def test_locate_reference_local_relative_syntax(self):
        source_file = Path(HTML_FILE_PATH)
        reference = "../shared/foo.png"  # go up one to the help dir
        resolved = HelpBuildUtils.locate_reference(source_file, reference)
        self.assertEqual(resolved, Path(f"{HELP_TOPIC_PATH}/shared/foo.png"))

    @unittest.skip
    def test_locate_reference_remote(self):
        source_file = Path(HTML_FILE_PATH)
        reference = "http://some.fake.server/foo.png"
        resolved = HelpBuildUtils.locate_reference(source_file, reference)
        self.assertIsNone(resolved)

    @unittest.skip
    def test_is_remote(self):
        reference = "http://some.fake.server/foo.png"
        is_remote = HelpBuildUtils.is_remote(reference)
        self.assertTrue(is_remote)

    @unittest.skip
    def test_locate_references_icons(self):
        source_file = Path(HTML_FILE_PATH)
        reference = "Icons.REFRESH_ICON"  # see Icons class
        location = HelpBuildUtils.locate_image_reference(source_file, reference)
        resolved = location.get_resolved_path()
        name = str(resolved.name)
        self.assertEqual(name, "reload3.png")
        self.assertTrue(location.is_runtime())
        self.assertFalse(location.is_remote())

    @unittest.skip
    def test_locate_references_icons_bad_name(self):
        source_file = Path(HTML_FILE_PATH)
        reference = "Icons.REFRESH_ICON_BAD"  # non-existent
        location = HelpBuildUtils.locate_image_reference(source_file, reference)
        resolved = location.get_resolved_path()
        self.assertIsNone(resolved)

if __name__ == "__main__":
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python. The original Java code seems to be part of some larger project and might require additional setup or imports in order to run correctly.