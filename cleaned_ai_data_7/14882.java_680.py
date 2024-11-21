import logging

class Servant:
    def __init__(self, name):
        self.name = name

    def feed(self, royalty):
        pass  # implement your logic here

    def give_wine(self, royalty):
        pass  # implement your logic here

    def give_compliments(self, guest):
        pass  # implement your logic here

    def check_if_you_will_be_hanged(self, guests):
        pass  # implement your logic here


class Royalty:
    @staticmethod
    def change_mood(royalty):
        pass  # implement your logic here


def scenario(servant: Servant, compliment: int) -> None:
    k = King()
    q = Queen()

    guests = [k, q]

    servant.feed(k)
    servant.feed(q)

    servant.give_wine(k)
    servant.give_wine(q)

    guest_to_compliment = guests[compliment]
    servant.give_compliments(guest_to_compliment)

    for royalty in guests:
        Royalty.change_mood(royalty)

    if not servant.check_if_you_will_be_hanged(guests):
        logging.info(f"{servant.name} will live another day")
    else:
        logging.info(f"Poor {servant.name}. His days are numbered")


class King:
    pass


class Queen:
    pass
