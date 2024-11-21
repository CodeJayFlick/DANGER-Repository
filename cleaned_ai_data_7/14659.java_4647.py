import requests
from bs4 import BeautifulSoup

class AlbumListPage:
    ALBUM_LIST_HTML_FILE = "album-list.html"
    PAGE_URL = f"file://{AUT_PATH}/{ALBUM_LIST_HTML_FILE}"

    def __init__(self, web_client):
        self.page = None
        super().__init__(web_client)

    def navigate_to_page(self):
        try:
            response = requests.get(PAGE_URL)
            self.page = BeautifulSoup(response.content, "html.parser")
        except Exception as e:
            print(f"Error: {e}")
        return self

    def is_at(self):
        return self.page.title == "Album List"

    def select_album(self, album_title):
        try:
            album_links = [a for a in self.page.find_all("tr", {"class": "album"}) if a.a]
            for link in album_links:
                if link.text.strip() == album_title:
                    link["href"]  # Simulate click
                    return AlbumPage(self.web_client)  # Return the selected page
        except Exception as e:
            print(f"Error: {e}")
        raise ValueError(f"No links with the album title: {album_title}")

class AlbumPage:
    def __init__(self, web_client):
        self.page = None
        super().__init__(web_client)

# Usage example
if __name__ == "__main__":
    # Initialize the web client and page object
    web_client = requests.Session()
    album_list_page = AlbumListPage(web_client)
    album_list_page.navigate_to_page()

    # Select an album by title
    selected_album = album_list_page.select_album("My Favorite Album")
