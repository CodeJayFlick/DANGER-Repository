# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class MobileClient:
    def __init__(self, business_delegate):
        self.business_delegate = business_delegate

    def playback_movie(self, movie):
        self.business_delegate.playback_movie(movie)
