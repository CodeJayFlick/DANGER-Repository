def merge(arr, temp, left, mid, right):
    i = left    # Starting index for left subarray
    j = mid + 1 # Starting index for right subarray
    k = left    # Starting index to be sorted

    while i <= mid and j <= right:
        if arr[i] <= arr[j]:
            temp[k] = arr[i]
            i += 1
        else:
            temp[k] = arr[j]
            j += 1
        k += 1

    # Copy the remaining elements of left subarray, if any
    while i <= mid:
        temp[k] = arr[i]
        i += 1
        k += 1

    # Copy the remaining elements of right subarray, if any
    while j <= right:
        temp[k] = arr[j]
        j += 1
        k += 1

    # Copy the sorted subarray into the original array
    for i in range(left, right + 1):
        arr[i] = temp[i]

def iterative_merge_sort(arr):
    n = len(arr)
    temp = [0] * n  # Temporary array to assist merging

    # Start with size 1 and keep doubling the size
    curr_size = 1
    while curr_size <= n - 1:
        left = 0
        while left < n - 1:
            mid = min((left + curr_size - 1), (n - 1))
            right = min((2 * curr_size + left - 1), (n - 1))

            merge(arr, temp, left, mid, right)
            left += 2 * curr_size

        curr_size = 2 * curr_size

# Example usage
arr = [12, 11, 13, 5, 6, 7]
print("Original array:", arr)
iterative_merge_sort(arr)
print("Sorted array:", arr)
