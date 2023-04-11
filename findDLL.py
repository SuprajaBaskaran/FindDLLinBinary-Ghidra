import json


listDLL = []
list_dll = {}
with open('strings.txt','r') as f, open('tempfile.json','w+') as f2:
   for line in f:  # looping string result file from the binary (Ghidra)
    #  print(line)
       if '.dll' in line:   # checks if the line in the text file contains '*.dll'
           listDLL.append(line)   # if yes, append the dll-text to the list 
   print(listDLL)   # prints the list (containing the DLL list from the binary's string results)
   for x in (listDLL):  # loops each element from the list
      print(x)
      isSysDLL = ''
      print("Current DLL:"+x)   # element from the collected DLL string list 
      list_dll["dllName"] = x   # assigning each element to a dictionary
      # print("Finding if System DLL..")
      with open('dll_list.txt','r') as f1:
        for line1 in f1:   # looping through the dll_list.txt (containing Windows DLL dataset)
          # print(line1)
          x = x.replace('"', '')
          x = x.strip()
          x = x.lower()
          line1 = line1.strip()
          line1 = line1.lower() 
          # print(line1)
          # print(x +" and "+ line1)
          if(str(x).__eq__(str(line1))):  # checks if the collected DLL string from binary is equal to each line from the DLL dataset 
            print("System DLL found!!\n")
            list_dll["dllCategory"] = "SystemDLL"
            isSysDLL = 'true'  # setting isSysDLL flag to true
            print(list_dll)
            f2.write(json.dumps(list_dll))
            break
      print(isSysDLL)
      if(isSysDLL != 'true'): # if it is not found in sysDLL list
        print("This is a custom DLL!!\n")
        list_dll["dllCategory"] = "CustomDLL"  # then it is a custom DLL
        print(list_dll)
        f2.write(json.dumps(list_dll))

  
           
  # # # # this JSON file should be looped and whichever belong to the custom DLL, function checks needs to be done!
  