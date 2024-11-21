import random

MAX_LEN = 100000

def merge_sort(arr):
    if len(arr) <= 1:
        return arr

    mid = (len(arr)) // 2
    left_half = arr[:mid]
    right_half = arr[mid:]

    left_half = merge_sort(left_half)
    right_half = merge_sort(right_half)

    return merge(left_half, right_half)


def merge(left, right):
    merged = []
    i = j = 0

    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            j += 1

    merged.extend(left[i:])
    merged.extend(right[j:])

    return merged


def main():
    random.seed(100)
    arr_merge = [random.randint(0, 9999) for _ in range(MAX_LEN)]
    arr_collections = arr_merge.copy()

    sorted_arr_collections = sorted(arr_collections)

    merge_sort(arr_merge)

    if arr_merge != sorted_arr_collections:
        print("MergeSort failed!")
    else:
        print("MergeSort successful!")

if __name__ == "__main__":
    main()
