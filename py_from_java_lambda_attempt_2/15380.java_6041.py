Here is the translation of the given Java code into Python:

```Python
def insertion_sort(arr):
    for i in range(1, len(arr)):
        num = arr[i]
        aux = i - 1
        
        while aux >= 0 and num < arr[aux]:
            arr[aux + 1] = arr[aux]
            aux -= 1
            
        arr[aux + 1] = num

arr = [10, 2, 6, 4, 3, 7, 5]

insertion_sort(arr)
print(str(arr))
```

This Python code does exactly the same thing as your given Java code. It sorts an array of integers using insertion sort algorithm and then prints out the sorted array.