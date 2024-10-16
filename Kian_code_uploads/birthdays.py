import datetime
import random


def get_birthdays(number_of_birthdays):
    birthdays = []
    for i in range(number_of_birthdays):
        start_of_year = datetime.date(2023, 1, 1)
        random_number_of_days = datetime.timedelta(random.randint(0, 364))
        birthday = start_of_year + random_number_of_days
        birthdays.append(birthday)
    return birthdays


def get_match(birthdays):
    if len(birthdays) == len(set(birthdays)):
        return None

    for a, birthday_A in enumerate(birthdays):
        for b, birthday_B in enumerate(birthdays[a + 1 :]):
            if birthday_A == birthday_B:
                return birthday_A


MONTHS = ('January', 'February', 'March', 'April', 'May', 'June', 'July',
          'August', 'September', 'October', 'November', 'December')

while True:
    print('How many birthdays should I generate? (Max 100)')
    response = input('> ')
    if response.isdecimal() and (0 < int(response) <= 365):
        num_b_days = int(response)
        break
print()

print('Here are', num_b_days, 'birthdays:')
birthdays = get_birthdays(num_b_days)
for i, birthday in enumerate(birthdays):
    if i != 0:
        print(', ', end='')
    month_name = MONTHS[birthday.month - 1]
    date_text = '{} {}'.format(month_name, birthday.day)
    print(date_text, end='')
print()
print()

match = get_match(birthdays)

print('In this simulation, ', end='')
if match != None:
    month_name = MONTHS[match.month - 1]
    date_text = '{} {}'.format(month_name, match.day)
    print('multiple people have a birthday on', date_text)
else:
    print('there are no matching birthdays.')
print()

print('Generating', num_b_days, 'random birthdays 100,000 times...')
input('Press Enter to begin...')

print('Running another 100,000 simulations.')
sim_match = 0
for i in range(100_000):
    if i % 10_000 == 0:
        print(i, 'simulations run...')
    birthdays = get_birthdays(num_b_days)
    if get_match(birthdays) != None:
        sim_match = sim_match + 1
print('100,000 simulations run.')

probability = round(sim_match / 100_000 * 100, 2)
print('Out of 100,000 simulations, there were matches', sim_match, 'times')
print('That means that', num_b_days, 'people have approximately a', probability, '% chance of')
print('having a matching birthday in their group.')
