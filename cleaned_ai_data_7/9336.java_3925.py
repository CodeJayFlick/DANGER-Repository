class DragDropManager:
    def is_start_drag_ok(self, drag_node: 'DragDropNode', drag_action: int) -> bool:
        pass  # Implement this method in the subclass.

    def is_drop_site_ok(self, dest_node: 'DragDropNode', e: object) -> bool:
        pass  # Implement this method in the subclass.

    def add(self, dest_node: 'DragDropNode', data: object, chosen: object, drop_action: int):
        pass  # Implement this method in the subclass.

    def move(self, source_nodes: list['DragDropNode']):
        pass  # Implement this method in the subclass.

    def get_acceptable_flavors(self) -> list[object]:
        return []  # Return an empty list for now. You should implement a way to determine acceptable flavors.

    def get_transferable(self, p: tuple[int]) -> object:
        pass  # Implement this method in the subclass.
