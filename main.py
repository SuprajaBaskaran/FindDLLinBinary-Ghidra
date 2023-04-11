# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.
from ordered_set import OrderedSet

call_list ={
    "createtoolhelp32snapshot": [0.5, 0],
    "process32first": [0.5, 1],
    "process32next": [0.5, 2],
    "enumprocess": [.5, 3],
    "openprocess": [0.6, 4],
    "loadlibrary": [.7, 5],
    "virtualallocex": [0.9, 6],
    "writeprocessmemory": [1.0, 7],
    "createremotethread": [1.0, 8]
}
binary_strings = []
thresh_hold = .4


def load_strings():
    with open("strings.txt") as file:
        for item in file:
            binary_strings.append(str(item))
    #print(binary_strings)


def search_calls():
    result = []
    for string in binary_strings:
        for i, (k,v) in enumerate(call_list.items()):
            if k.lower() in string.lower():
                result.append(k.lower())
    result = list(OrderedSet(result))
    print(result)
    return result


def is_suspicious(result):
    sum = 0.0
    for res in result:
        sum = sum + call_list[res][0]

    avg = sum/float(len(result))
    if avg >= thresh_hold:
        print(str(avg)+ ' suspicious')
        return True
    print('safe')
    return False


def is_sorted_ascending(lst):
    for i in range(1, len(lst)):
        if lst[i] < lst[i - 1]:
            return False
    return True


def is_sorted_descending(lst):
    for i in range(1,len(lst)):
        if lst[i] > lst[i-1]:
            return False
    return True


def max_sorted_sublist(lst):
    tmp = [[]]
    max_len = 0
    for i in range(len(lst) + 1):
        for j in range(i + 1, len(lst) + 1):
            sub = lst[i:j]
            tmp.append(sub)

    for i in range(len(tmp)):
        #print(B[i])
        if is_sorted_descending(tmp[i]) or is_sorted_ascending(tmp[i]):
            if max_len < len(tmp[i]):
                max_len = len(tmp[i])
    return max_len


def pattern_match(result):
    #search in result if they appear in a particular order given in call_list
    pattern = []
    for item in result:
        pattern.append(call_list[item][1])
    print(pattern)
    len = max_sorted_sublist(pattern)
    return len >= 3


if __name__ == '__main__':
    load_strings()
    result = search_calls()
    if is_suspicious(result) and pattern_match(result):
        print('Warning: Your Binary Might Cause Potential DLL Injection')
    else:
        print('found nothing')

