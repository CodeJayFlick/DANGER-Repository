Here is the equivalent Python code:

```Python
import random
from datetime import date, timedelta

class PetData:
    breeds = ["Afghan Hound", "Beagle", "Bernese Mountain Dog", 
              "Bloodhound", "Dalmatian", "Jack Russell Terrier", 
              "Norwegian Elkhound"]
    
    names = ["Bailey", "Bella", "Max", "Lucy", "Charlie", "Molly", 
             "Buddy", "Daisy", "Rocky", "Maggie", "Jake", "Sophie", 
             "Jack", "Sadie", "Toby", "Chloe", "Cody", "Bailey", "Buster", 
             "Lola", "Duke", "Zoe", "Cooper", "Abby", "Riley", "Ginger", 
             "Harley", "Roxy", "Bear", "Gracie", "Tucker", "Coco", "Murphy", 
             "Sasha", "Lucky", "Lily", "Oliver", "Angel", "Sam", "Princess", 
             "Oscar", "Emma", "Teddy", "Annie", "Winston", "Rosie"]
    
    @classmethod
    def get_breeds(cls):
        return cls.breeds
    
    @classmethod
    def get_names(cls):
        return cls.names
    
    @classmethod
    def get_random_breed(cls):
        return random.choice(cls.breeds)
    
    @classmethod
    def get_random_name(cls):
        return random.choice(cls.names)
    
    @classmethod
    def get_random_dob(cls):
        today = date.today()
        year = random.randint(today.year - 15, today.year)
        day_of_year = random.randint(1, 365)
        
        dob = date(year=year, month=1, day=day_of_year)
        
        return dob
```

Note that Python does not have a direct equivalent to Java's `ThreadLocalRandom`. Instead, we use the built-in `random` module. Also, Python has no concept of static methods or variables like in Java; instead, we define classmethods using the `@classmethod` decorator.