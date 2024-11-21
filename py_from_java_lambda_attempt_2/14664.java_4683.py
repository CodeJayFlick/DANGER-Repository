Here is the translation of the Java code into Python:

```Python
import logging
from htmlunit import WebClient, HtmlPage, HtmlTextInput, HtmlSelect, HtmlSubmitInput, IOException

class AlbumPage:
    ALBUM_PAGE_HTML_FILE = "album-page.html"
    PAGE_URL = f"file:{AUT_PATH}/{ALBUM_PAGE_HTML_FILE}"

    def __init__(self, web_client):
        self.web_client = web_client
        self.page = None

    def navigate_to_page(self) -> 'AlbumPage':
        try:
            self.page = self.web_client.get_page(PAGE_URL)
        except IOException as e:
            logging.error("An error occurred on navigate_to_page.", e)

        return self

    def is_at(self):
        if not self.page or "Album Page" != self.page.get_title_text():
            return False
        return True

    def change_album_title(self, album_title: str) -> 'AlbumPage':
        album_title_input = self.page.get_element_by_id("albumTitle")
        album_title_input.set_text(album_title)
        return self

    def change_artist(self, artist: str) -> 'AlbumPage':
        artist_input = self.page.get_element_by_id("albumArtist")
        artist_input.set_text(artist)
        return self

    def change_album_year(self, year: int) -> 'AlbumPage':
        album_year_select = self.page.get_element_by_id("albumYear")
        option = album_year_select.get_option_by_value(str(year))
        album_year_select.select(option, True)
        return self

    def change_album_rating(self, album_rating: str) -> 'AlbumPage':
        album_rating_input = self.page.get_element_by_id("albumRating")
        album_rating_input.set_text(album_rating)
        return self

    def change_number_of_songs(self, number_of_songs: int) -> 'AlbumPage':
        number_of_songs_field = self.page.get_element_by_id("numberOfSongs")
        number_of_songs_field.set_text(str(number_of_songs))
        return self

    def cancel_changes(self) -> 'AlbumListPage':
        try:
            button = self.page.get_element_by_id("cancelButton")
            button.click()
        except IOException as e:
            logging.error("An error occurred on cancelChanges.", e)

        return AlbumListPage(self.web_client)

    def save_changes(self) -> 'AlbumPage':
        try:
            button = self.page.get_element_by_id("saveButton")
            button.click()
        except IOException as e:
            logging.error("An error occurred on saveChanges.", e)

        return self

class AlbumListPage:
    pass
```

Please note that the `AUT_PATH` variable is not defined in this code. You would need to define it or replace its usage with your actual path.