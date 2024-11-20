import unittest.mock as mock
from unittest import TestCase


class BusinessDelegateTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.netflix_service = mock.Mock()
        cls.youtube_service = mock.Mock()

    def test_business_delegate(self):
        business_lookup = self.netflix_service
        business_delegate = self.netflix_service

        client = MobileClient(business_delegate)

        # action
        client.playback_movie("Die hard")

        # verifying that the businessDelegate was used by client during playbackMovie() method.
        self.netflix_service.assert_called_once_with(anystring())

        self.netflix_service.do_processing()

        # action
        client.playback_movie("Maradona")

        # verifying that the businessDelegate was used by client during doTask() method.
        self.youtube_service.assert_called_once_with(anystring())
        self.youtube_service.do_processing()


class MobileClient:
    def __init__(self, business_delegate):
        self.business_delegate = business_delegate

    def playback_movie(self, movie_name):
        self.business_delegate.playback_movie(movie_name)


if __name__ == "__main__":
    unittest.main()
