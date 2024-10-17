input_string = input('Please enter the string > ')
letters = list('abcdefghijklmnopqrstuvwxyz')
input_list = list(input_string.lower())
result = {}

for i in letters:
    result[i] = 0

for i in input_list:
    if i in result:
        result[i] += 1

result = dict(sorted(result.items(), key=lambda item: item[1], reverse=True))

for i in result:
    if result.get(i) > 0:
        print(f'{i}: {result.get(i)}')
