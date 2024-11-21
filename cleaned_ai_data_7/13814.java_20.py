import logging

class NetflixService:
    def do_processing(self):
        logging.info("NetflixService is now processing")

if __name__ == "__main__":
    netflix_service = NetflixService()
    netflix_service.do_processing()

