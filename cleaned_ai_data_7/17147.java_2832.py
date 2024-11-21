class IEntityMNode:
    def add_alias(self, alias: str, child: 'IMeasurementMNode') -> bool:
        pass  # Implement this method in your subclass

    def delete_alias_child(self, alias: str) -> None:
        pass  # Implement this method in your subclass

    @property
    def alias_children(self) -> dict[str, 'IMeasurementMNode']:
        return {}  # Initialize with an empty dictionary

    @alias_children.setter
    def set_alias_children(self, value: dict[str, 'IMeasurementMNode']) -> None:
        pass  # Implement this method in your subclass

    def is_use_template(self) -> bool:
        pass  # Implement this method in your subclass

    def set_use_template(self, use_template: bool) -> None:
        pass  # Implement this method in your subclass

    def get_last_cache_container(self, measurement_id: str) -> 'ILastCacheContainer':
        return None  # Return a default value or implement this method in your subclass

    @property
    def template_last_caches(self) -> dict[str, 'ILastCacheContainer']:
        return {}  # Initialize with an empty dictionary

    @template_last_caches.setter
    def set_template_last_caches(self, value: dict[str, 'ILastCacheContainer']) -> None:
        pass  # Implement this method in your subclass
