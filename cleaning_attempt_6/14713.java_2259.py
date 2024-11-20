class DisplayedAlbums:
    def __init__(self):
        self.albums = []

    def add_album(self, title, artist, displayed, composer):
        album = {"title": title, "artist": artist, "displayed": displayed, "composer": composer}
        self.albums.append(album)

def test_add_displayed_albums():
    displayed_albums = DisplayedAlbums()
    
    # Test add with display
    displayed_albums.add_album("title", "artist", True, "composer")
    assert displayed_albums.albums[0]["composer"] == "composer"

    # Test add without display
    displayed_albums.add_album("title", "artist", False, "composer")
    assert displayed_albums.albums[0]["composer"] == ""

if __name__ == "__main__":
    test_add_displayed_albums()
