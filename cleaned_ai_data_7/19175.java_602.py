import org.bukkit.entity.Ageable
from typing import Union

class EntityUtils:
    HAS_PIGLINS = hasattr(Ageable, 'isBaby')

    @staticmethod
    def is_ageable(entity: object) -> bool:
        if isinstance(entity, Ageable):
            return True
        elif entity.__class__.__name__ == "Zombie":
            return True
        else:
            return EntityUtils.HAS_PIGLINS and (entity.__class__.__name__ in ["Piglin", "Zoglin"])

    @staticmethod
    def get_age(entity: object) -> int:
        if isinstance(entity, Ageable):
            return entity.getAge()
        elif entity.__class__.__name__ == "Zombie":
            return -1 if entity.isBaby() else 0
        elif EntityUtils.HAS_PIGLINS and (entity.__class__.__name__ in ["Piglin", "Zoglin"]):
            return -1 if hasattr(entity, 'isBaby') and getattr(entity, 'isBaby') else 0
        return 0

    @staticmethod
    def set_age(entity: object, age: int) -> None:
        if isinstance(entity, Ageable):
            entity.setAge(age)
        elif entity.__class__.__name__ == "Zombie":
            entity.setBaby(age < 0)
        elif EntityUtils.HAS_PIGLINS and (entity.__class__.__name__ in ["Piglin", "Zoglin"]):
            if isinstance(entity, Piglin) or isinstance(entity, Zoglin):
                entity.setBaby(age < 0)

    @staticmethod
    def set_baby(entity: object) -> None:
        EntityUtils.set_age(entity, -24000)

    @staticmethod
    def set_adult(entity: object) -> None:
        EntityUtils.set_age(entity, 0)

    @staticmethod
    def is_adult(entity: object) -> bool:
        return EntityUtils.get_age(entity) >= 0

# Usage example:

if __name__ == "__main__":
    entity = Ageable()  # Replace with your actual entity instance.
    print(EntityUtils.is_ageable(entity))  # Check if the entity is ageable
    print(EntityUtils.get_age(entity))  # Get the age of the entity
    EntityUtils.set_age(entity, -24000)  # Set the age to baby
    print(EntityUtils.is_adult(entity))  # Check if the entity is an adult now
