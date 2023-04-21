
import json
from ordered_set import OrderedSet
from findDLL import *
#from PyQt5 import QtCore, QtGui, QtWidgets, uic
#from Practical malware Chapter 12 : DLL Injection
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
custom_dlls = []
system_dlls = []
thresh_hold = .4


def load_dlls():
    #loads all the system dlls and custom dlls in two seperate lists
    data = ''
    with open('tempfile.json', 'r') as f:
        for line in f:
            data+=line
    #print(data)
    data1 = data.split('}')
    for d in data1:
        if len(d) >= 2:
            name, category = d.split(',')
            if 'CustomDLL' in category:
                xx = name.split(':')[1].split('.')[0]+'.dll'
                yy = xx.split('\"')
                for y in yy:
                    if 'dll' in y:
                        custom_dlls.append(y)
            else:
                xx = name.split(':')[1].split('.')[0] + '.dll'
                yy = xx.split('\"')
                for y in yy:
                    if 'dll' in y:
                        system_dlls.append(y)


    print(custom_dlls)
    print(system_dlls)
    #print(data1)
    #file = open('dll_names.json')
    #data = file(file)
    #print(data)


def load_strings():
    ## loads all the strings in a list
    with open("strings.txt") as file:
        for item in file:
            binary_strings.append(str(item))
    #print(binary_strings)


def search_calls():
    ##search for all the function calls that match the call list
    result = []
    for string in binary_strings:
        for i, (k,v) in enumerate(call_list.items()):
            if k.lower() in string.lower():
                result.append(k.lower())
    result = list(OrderedSet(result))
    print(result)
    return result


def is_suspicious(result):
    ##flag suspicious if the weighted average of the function calls found crosses a certain threshold
    ##Future work: Find tune this threshold with more malicious binaries, possibly leverage ML
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
    ##checks if a list is sorted in ascending order
    for i in range(1, len(lst)):
        if lst[i] < lst[i - 1]:
            return False
    return True


def is_sorted_descending(lst):
    #checks if a list is sorted in descending order
    for i in range(1,len(lst)):
        if lst[i] > lst[i-1]:
            return False
    return True


def max_sorted_sublist(lst):
    #returns length of maximum sorted sublist (ascending or descending order)
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
    #if the function list contains a sorted sublist (ascending or descending) order and its length is more than three meaning atleast
    #three function calls are present in the pattern we mark it as suspicious
    len = max_sorted_sublist(pattern)
    return len >= 3


