import os
import win32api
import winreg as _winreg

def getDefaultIcon(filename):
    '''Retrieve the default icon of a filename'''
    (root, extension) = os.path.splitext(filename)
    if extension:
        try:
            value_name = _winreg.QueryValue(_winreg.HKEY_CLASSES_ROOT,
                                            extension)
        except _winreg.error:
            value_name = None
    else:
        value_name = None
    if value_name:
        try:
            icon = _winreg.QueryValue(_winreg.HKEY_CLASSES_ROOT,
                                      value_name + "\\DefaultIcon")
        except _winreg.error:
            icon = None
    else:
        icon = None
    return icon


if __name__ == "__main__":
    print(getDefaultIcon("C:\\Program Files\\Mozilla Firefox\\firefox.exe"))