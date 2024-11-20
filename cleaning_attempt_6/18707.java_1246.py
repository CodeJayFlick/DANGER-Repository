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
    
    def get_breeds(self):
        return self.breeds
    
    def get_names(self):
        return self.names
    
    def random_breed(self):
        return random.choice(self.breeds)
    
    def random_name(self):
        return random.choice(self.names)
    
    def random_dob(self):
        year = random.randint(2005, date.today().year - 15)
        day_of_year = random.randint(1, 365)
        
        dob = date(year=year, month=1, day=day_of_year) + timedelta(days=-day_of_year+1)
        
        return dob
