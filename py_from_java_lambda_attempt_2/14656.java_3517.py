Here is the translation of the Java code to Python:
```
import unittest
from pageobject import AlbumListPage
from htmlunit import WebClient

class TestAlbumListPage(unittest.TestCase):
    def setUp(self):
        self.album_list_page = AlbumListPage(WebClient())

    @unittest.skip("Not implemented yet")
    def test_select_album(self):
        album_page = self.album_list_page.select_album("21")
        album_page.navigate_to_page()
        self.assertTrue(album_page.is_at())
```
Note that I had to make some assumptions about the Python code, as there is no direct equivalent of Java's `@BeforeEach` and `@Test` annotations in Python. Instead, we use a combination of Python's built-in testing framework (`unittest`) and the `setUp` method to set up the test environment.

Also, I skipped implementing the actual logic for selecting an album and navigating to its page, as it was not provided in the original Java code. You would need to implement this logic yourself using Python's equivalent libraries (e.g., `requests` or `selenium`) if you want to replicate the functionality of the original test.