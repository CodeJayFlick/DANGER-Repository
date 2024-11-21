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
