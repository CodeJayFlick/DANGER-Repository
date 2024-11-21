Here is the translation of the Java code to Python:
```python
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
```
Note that I had to make some assumptions about the Java code, as it was not provided in its entirety. Specifically:

* The `AUT_PATH` variable is assumed to be a constant or environment variable containing the path to the HTML file.
* The `Page` class and its methods are assumed to be part of the same package as the `AlbumListPage` class.

Also, I used the `requests` library for making HTTP requests and parsing HTML content. If you prefer using another library (e.g., `pyquery` or `lxml`) for this purpose, feel free to modify the code accordingly.