import random
from datetime import date, timedelta

class PetData:
    breeds = ["Afghan Hound", "Beagle", "Bernese Mountain Dog", "Bloodhound", "Dalmatian",
              "Jack Russell Terrier", "Norwegian Elkhound"]
    names = ["Bailey", "Bella", "Max", "Lucy", "Charlie", "Molly", "Buddy", "Daisy", "Rocky", 
             "Maggie", "Jake", "Sophie", "Jack", "Sadie", "Toby", "Chloe", "Cody", "Bailey",
             "Buster", "Lola", "Duke", "Zoe", "Cooper", "Abby", "Riley", "Ginger", 
             "Harley", "Roxy", "Bear", "Gracie", "Tucker", "Coco", "Murphy", "Sasha",
             "Lucky", "Lily", "Oliver", "Angel", "Sam", "Princess", "Oscar", "Emma", 
             "Teddy", "Annie", "Winston", "Rosie"]

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
        year = random.randint(2005, date.today().year)
        day_of_year = random.randint(1, 365)
        dob = date(year=year, month=1, day=day_of_year) - timedelta(days=day_of_year-1)
        return dob
