import pefile
import os

def list_files(dir, ext):
    file_list = []
    for root, dirs, files in os.walk(dir):
        for file in files:
            if file.endswith(ext):
                 path = os.path.join(root, file)
                 file_list.append(path)
    return file_list


dir_path = "C:\\Windows\\System32\\"
file_ext = "user32.dll"

files = list_files(dir_path, file_ext)

searched_import = "MSVBVM60.DLL"

for f_path in files:
    #path = "C:\Program Files (x86)\Kakao\KakaoTalk\KakaoTalk.exe"
    try:
        pe =  pefile.PE(f_path)
    except pefile.PEFormatError :
        print(f_path + "is NOT PE!")
        continue

    pe = pefile.PE(f_path)

    #print "\nSections:"
    #for section in pe.sections:
    #  print (section.Name, hex(section.VirtualAddress),
    #    hex(section.Misc_VirtualSize), section.SizeOfRawData )

    ## If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:
    pe.parse_data_directories()

    #print "\nImports:"

    isFound = False
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
      print(entry.dll)
      for imp in entry.imports:
        print('\t', hex(imp.address), imp.name)
        print('----')

    if isFound == True :
        print(f_path + " [YES]")
    else :
         print(f_path + " [NO]")

    for exp in pe.DIRECTORY_ENTRY_EXPORT:
        print('\t', hex(exp.address), exp.name)
  #for imp in entry.imports:
  #  print '\t', hex(imp.address), imp.name