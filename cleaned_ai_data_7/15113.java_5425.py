from typing import Optional, Stream

class HotelDAO:
    def get_all(self) -> list:
        # Implement your logic here to return all rooms as a list
        pass

    def get_by_id(self, room_id: int) -> Optional[dict]:
        # Implement your logic here to return the room with the given id or None if not found
        pass

    def add_room(self, room: dict) -> bool:
        # Implement your logic here to add a new room and return True on success, False otherwise
        pass

    def update_room(self, room: dict) -> bool:
        # Implement your logic here to update an existing room and return True on success, False otherwise
        pass

    def delete_room(self, room: dict) -> bool:
        # Implement your logic here to delete a room and return True on success, False otherwise
        pass
