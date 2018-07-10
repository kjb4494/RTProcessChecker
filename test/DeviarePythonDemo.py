# Main ==================================================================

import win32com.client
import ctypes

from test.EventHandlers import NktSpyMgrEvents
from test.AuxFunctions import *

spyManager = win32com.client.DispatchWithEvents('DeviareCOM.NktSpyMgr', NktSpyMgrEvents)
spyManager.Initialize()

StartNotepadAndHook(spyManager)

MessageBox = ctypes.windll.user32.MessageBoxA
MessageBox(None, 'Press OK to end the demo.', 'Deviare Python Demo', 0)
