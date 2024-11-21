import logging
from micronaut import run_app

logging.basicConfig(level=logging TRACE)

def main():
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.TRACE)
    run_app(__file__)

if __name__ == "__main__":
    main()
