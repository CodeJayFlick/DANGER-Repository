def is_sorted(array):
    sort = True
    for i in range(len(array) - 1):
        if array[i] > array[i + 1]:
            sort = False
    return sort


def bubble_sort(array):
    done = True

    for j in range(len(array)):
        for i in range(len(array) - 1 - j):
            if array[i] > array[i + 1]:
                done = False
                array[i], array[i + 1] = array[i + 1], array[i]
        if done:
            break

    return array


def selection_sort(array):
    done = True

    for i in range(len(array)):
        max_item = 0  # Location of the largest item

        for j in range(len(array) - i):
            if array[j] > array[max_item]:
                max_item = j
            else:
                done = False

        if done:
            break

        location = len(array) - i - 1
        if max_item != location:
            array[max_item], array[location] = array[location], array[max_item]

    return array


def insertion_sort(array):
    for i in range(1, len(array)):
        for k in range(i):
            if array[i] < array[k]:
                # Lift the element
                temp = array[i]
                counter = i
                while counter >= k:
                    array[counter] = array[counter - 1]
                    counter -= 1
                array[k] = temp

    return array


def __recursive_merge__(array):
    # Base case, nothing to sort
    if len(array) == 1:
        return array

    # Split the array into two halves
    middle = int(len(array) / 2)
    first_half = array[middle:]
    second_half = array[:middle]

    # Recursively sort the first and second half
    first_half = __recursive_merge__(first_half)
    second_half = __recursive_merge__(second_half)

    # Merge the two halves
    complete_array = __merge__(first_half, second_half)

    return complete_array


def __merge__(array1, array2):
    merged_array = []
    i = 0  # counter for array 1
    j = 0  # counter for array 2

    while i != len(array1) and j != len(array2):
        if array1[i] < array2[j]:
            merged_array.append(array1[i])
            i += 1
        else:
            merged_array.append(array2[j])
            j += 1
    # Doesn't matter which runs out first, loop with empty array never executes
    while i != len(array1):
        merged_array.append(array1[i])
        i += 1
    while j != len(array2):
        merged_array.append(array2[j])
        j += 1

    return merged_array


def merge_sort(array):
    sorted_array = __recursive_merge__(array)
    return sorted_array


def __recursive_quick__(low, high, array):
    if len(array) <= 1:
        return array

    if len(array) == 2:
        new_array = insertion_sort(array)
        return new_array

    # We want the middle element of the first three elements as the pivot
    minimum = min(array[0], array[1], array[2])
    maximum = max(array[0], array[1], array[2])
    if array[0] != minimum and array[0] != maximum:
        pivot = 0
    elif array[1] != minimum and array[0] != maximum:
        pivot = 1
    else:
        pivot = 2

    # Split the elements based on their value relative to the pivot
    lower_half = []
    upper_half = []

    # Split the array into two halves: one which contains all elements less than the pivot
    # and one which contains all the values which are greater.
    for i in range(len(array)):
        if i == pivot:
            continue
        if array[i] < array[pivot]:
            lower_half.append(array[i])
        else:
            upper_half.append(array[i])

    # Now, we call QuickSort on the lower and upper halves
    lower_half = __recursive_quick__(lower_half)
    upper_half = __recursive_quick__(upper_half)

    temp = [array[pivot]]
    complete_array = lower_half + temp + upper_half

    return complete_array


def quick_sort(array):
    array = __recursive_quick__(0, len(array) - 1, array)
    return array


def heap_sort(array):
    # First, we need to heapify the array
    # An array is a max heap if each element i is greater than elements 2i + 1 and 2i + 2
    # second half of array is already a heap
    counter = int(len(array) / 2) - 1
    while counter >= 0:
        counter2 = counter
        while 2 * counter2 + 1 < len(array):
            if len(array) <= 2 * counter2 + 2:
                large_location = 2 * counter2 + 1
            elif array[2 * counter2 + 1] > array[2 * counter2 + 2]:
                large_location = 2 * counter2 + 1
            else:
                large_location = 2 * counter2 + 2

            if array[large_location] > array[counter2]:
                array[large_location], array[counter2] = array[counter2], array[large_location]

            counter2 = large_location

        counter -= 1
    # We now have a heap, so now we repeatedly swap the first element into the last
    for i in range(len(array)):
        temp = array[0]
        array[0] = array[len(array) - i - 1]
        array[len(array) - i - 1] = temp

        # Now, we need to trickle element 0 down
        counter = 0
        while 2 * counter + 1 < len(array) - i - 1:
            if len(array) - i - 1 <= 2 * counter + 2:
                large_location = 2 * counter + 1
            elif array[2 * counter + 1] > array[2 * counter + 2]:
                large_location = 2 * counter + 1
            else:
                large_location = 2 * counter + 2

            if array[large_location] > array[counter]:
                array[large_location], array[counter] = array[counter], array[large_location]

            counter = large_location

    return array
