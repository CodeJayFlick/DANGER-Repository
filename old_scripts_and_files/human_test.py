import random

max_num = 100 # The largest possible value
length = 20 # Length of random array
array = []

for i in range(length):
    array.append(random.randint(1, max_num))

print(f'Random array of length {length}: {array}')

# Bubble sort data
for i in range(len(array)):
    done = True
    # i items are already sorted
    for j in range(len(array) - i - 1):
        if array[j] > array[j + 1]:
            array[j], array[j + 1] = array[j + 1], array[j]
            done = False
    if done:
        break

print(f'Sorted array: {array}')
