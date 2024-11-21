import unittest
from pageobject import AlbumListPage
from selenium import webdriver


class TestAlbumListPage(unittest.TestCase):

    def setUp(self):
        self.album_list_page = AlbumListPage(webdriver.Chrome())

    def test_select_album(self):
        album_page = self.album_list_page.select_album("21")
        album_page.navigate_to_page()
        self.assertTrue(album_page.is_at())


if __name__ == '__main__':
    unittest.main()
