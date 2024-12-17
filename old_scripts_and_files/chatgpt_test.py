import random

def generate_random_array(size, min_value, max_value):
    """Generates an array of random integers."""
    return [random.randint(min_value, max_value) for _ in range(size)]

def bubble_sort(arr):
    """Manually sorts an array using the bubble sort algorithm."""
    n = len(arr)
    for i in range(n):
        # Last i elements are already sorted
        for j in range(0, n - i - 1):
            if arr[j] > arr[j + 1]:
                # Swap if the element found is greater than the next element
                arr[j], arr[j + 1] = arr[j + 1], arr[j]
    return arr

def main():
    # Generate a random array of integers
    array_size = 10
    min_value = 1
    max_value = 100
    random_array = generate_random_array(array_size, min_value, max_value)

    print("Original Array:", random_array)

    # Sort the array manually
    sorted_array = bubble_sort(random_array)

    print("Sorted Array:", sorted_array)

if __name__ == "__main__":
    main()
