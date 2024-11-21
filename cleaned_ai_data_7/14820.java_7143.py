import logging

class SlidingDoor:
    def __enter__(self):
        print("Opening sliding door...")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            print(f"Error: {exc_type.__name__} - {exc_val}")
        else:
            print("Closing sliding door...")

class TreasureChest:
    def __enter__(self):
        print("Opening treasure chest...")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            print(f"Error: {exc_type.__name__} - {exc_val}")
        else:
            print("Closing treasure chest...")

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger()

def main():
    with SlidingDoor() as sliding_door:
        LOGGER.info("Walking in.")
    
    with TreasureChest() as treasure_chest:
        LOGGER.info("Looting contents.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
