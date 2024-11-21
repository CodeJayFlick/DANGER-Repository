class PresentationModel:
    def __init__(self, data_of_albums):
        self.data = data_of_albums
        self.selected_album_number = 1
        self.selected_album = self.data.get_albums()[0]

    def set_selected_album_number(self, album_number):
        print(f"Change select number from {self.selected_album_number} to {album_number}")
        self.selected_album_number = album_number
        self.selected_album = self.data.get_albums()[self.selected_album_number - 1]

    @property
    def title(self):
        return self.selected_album.title

    @title.setter
    def title(self, value):
        print(f"Change album title from {self.selected_album.title} to {value}")
        self.selected_album.title = value

    @property
    def artist(self):
        return self.selected_album.artist

    @artist.setter
    def artist(self, value):
        print(f"Change album artist from {self.selected_album.artist} to {value}")
        self.selected_album.artist = value

    def get_is_classical(self):
        return self.selected_album.is_classical()

    def set_is_classical(self, value):
        if not self.selected_album.is_classical():
            print("Composer can not be changed")
        else:
            print(f"Change album isClassical from {self.selected_album.is_classical()} to {value}")
            self.selected_album.set_classical(value)

    @property
    def composer(self):
        return "" if not self.selected_album.is_classical() else self.selected_album.composer

    @composer.setter
    def composer(self, value):
        if self.selected_album.is_classical():
            print(f"Change album composer from {self.selected_album.composer} to {value}")
            self.selected_album.composer = value
        else:
            print("Composer can not be changed")

    def get_album_list(self):
        return [album.title for album in self.data.get_albums()]
