class PresentationModel:
    def __init__(self):
        self.album_list = ["HQ", "The Rough Dancer and Cyclical Night", "The Black Light", "Symphony No.5"]
        self.title = ""
        self.artist = ""
        self.is_classical = False
        self.composer = ""

    @staticmethod
    def album_data_set():
        return {"HQ": "", "The Rough Dancer and Cyclical Night": "", "The Black Light": "", "Symphony No.5": ""}

class PresentationTest:
    def test_create_album_list(self):
        model = PresentationModel()
        list_ = model.get_album_list()
        self.assertEqual(str(model.album_list), str(list_))

    def test_set_selected_album_number_1(self):
        model = PresentationModel()
        select_id = 2
        model.set_selected_album_number(select_id)
        self.assertEqual(model.album_list[select_id - 1], model.title)

    def test_set_selected_album_number_2(self):
        model = PresentationModel()
        select_id = 4
        model.set_selected_album_number(select_id)
        self.assertEqual(model.album_list[select_id - 1], model.title)

    def test_set_title_1(self):
        model = PresentationModel()
        test_title = "TestTile"
        model.set_title(test_title)
        self.assertEqual(test_title, model.title)

    def test_set_title_2(self):
        model = PresentationModel()
        test_title = ""
        model.set_title(test_title)
        self.assertEqual(test_title, model.title)

    def test_set_artist_1(self):
        model = PresentationModel()
        test_artist = "TestArtist"
        model.set_artist(test_artist)
        self.assertEqual(test_artist, model.artist)

    def test_set_artist_2(self):
        model = PresentationModel()
        test_artist = ""
        model.set_artist(test_artist)
        self.assertEqual(test_artist, model.artist)

    def test_set_is_classical(self):
        model = PresentationModel()
        model.set_is_classical(True)
        self.assertTrue(model.is_classical)

    def test_set_composer_false(self):
        model = PresentationModel()
        test_composer = "TestComposer"
        model.set_is_classical(False)
        model.set_composer(test_composer)
        self.assertEqual("", model.composer)

    def test_set_composer_true(self):
        model = PresentationModel()
        test_composer = "TestComposer"
        model.set_is_classical(True)
        model.set_composer(test_composer)
        self.assertEqual(test_composer, model.composer)


if __name__ == "__main__":
    import unittest
    class Test(PresentationTest, unittest.TestCase):
        def test_create_album_list(self):
            pass

        def test_set_selected_album_number_1(self):
            pass

        def test_set_selected_album_number_2(self):
            pass

        def test_set_title_1(self):
            pass

        def test_set_title_2(self):
            pass

        def test_set_artist_1(self):
            pass

        def test_set_artist_2(self):
            pass

        def test_set_is_classical(self):
            pass

        def test_set_composer_false(self):
            pass

        def test_set_composer_true(self):
            pass
    unittest.main()
