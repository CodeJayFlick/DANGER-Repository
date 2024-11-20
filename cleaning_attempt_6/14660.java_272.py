class AlbumPage:
    def __init__(self):
        self.page = None

    def navigate_to_page(self):
        try:
            self.page = self.web_client.get("file:album-page.html")
        except Exception as e:
            print(str(e))
        return self

    def is_at(self):
        if self.page and "Album Page" == self.page.title():
            return True
        else:
            return False

    def change_album_title(self, album_title):
        try:
            album_title_input_text_field = self.page.get_element_by_id("albumTitle")
            album_title_input_text_field.set_value(album_title)
        except Exception as e:
            print(str(e))
        return self

    def change_artist(self, artist):
        try:
            artist_input_text_field = self.page.get_element_by_id("albumArtist")
            artist_input_text_field.set_value(artist)
        except Exception as e:
            print(str(e))
        return self

    def change_album_year(self, year):
        try:
            album_year_select_option = self.page.get_element_by_id("albumYear")
            year_option = album_year_select_option.get_option_by_value(str(year))
            album_year_select_option.set_selected_attribute(year_option, True)
        except Exception as e:
            print(str(e))
        return self

    def change_album_rating(self, album_rating):
        try:
            album_rating_input_text_field = self.page.get_element_by_id("albumRating")
            album_rating_input_text_field.set_value(album_rating)
        except Exception as e:
            print(str(e))
        return self

    def change_number_of_songs(self, number_of_songs):
        try:
            number_of_songs_number_field = self.page.get_element_by_id("numberOfSongs")
            number_of_songs_number_field.set_value(str(number_of_songs))
        except Exception as e:
            print(str(e))
        return self

    def cancel_changes(self):
        try:
            cancel_button = self.page.get_element_by_id("cancelButton")
            cancel_button.click()
        except Exception as e:
            print(str(e))
        return AlbumListPage()

    def save_changes(self):
        try:
            save_button = self.page.get_element_by_id("saveButton")
            save_button.click()
        except Exception as e:
            print(str(e))
        return self
