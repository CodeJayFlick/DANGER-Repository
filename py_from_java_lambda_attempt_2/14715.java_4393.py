Here is the translation of the Java code to Python:
```
import unittest

class ViewTest(unittest.TestCase):
    album_list = ["HQ", "The Rough Dancer and Cyclical Night", "The Black Light", "Symphony No.5"]

    def test_save_set_artist_and_title(self):
        view = View()
        view.create_view()
        title = "testTitle"
        artist = "testArtist"
        view.txt_artist.set_text(artist)
        view.txt_title.set_text(title)
        view.save_to_pmod()
        view.load_from_pmod()
        self.assertEqual(view.model.get_title(), title)
        self.assertEqual(view.model.get_artist(), artist)

    def test_save_set_classical_and_composer(self):
        view = View()
        view.create_view()
        is_classical = True
        composer = "testComposer"
        view.chk_classical.set_selected(is_classical)
        view.txt_composer.set_text(composer)
        view.save_to_pmod()
        view.load_from_pmod()
        self.assertTrue(view.model.get_is_classical())
        self.assertEqual(view.model.get_composer(), composer)

    def test_load_1(self):
        view = View()
        view.create_view()
        view.model.set_selected_album_number(2)
        view.load_from_pmod()
        self.assertEqual(album_list[1], view.model.get_title())

    def test_load_2(self):
        view = View()
        view.create_view()
        view.model.set_selected_album_number(4)
        view.load_from_pmod()
        self.assertEqual(album_list[3], view.model.get_title())
```
Note that I assumed the following:

* The `View` class is defined elsewhere in your Python code, and has methods like `create_view`, `txt_artist`, etc.
* The `Model` class is also defined elsewhere, and has attributes like `get_title`, `set_selected_album_number`, etc.

If these assumptions are incorrect, please let me know and I'll be happy to help you further!