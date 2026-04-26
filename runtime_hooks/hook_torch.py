"""
PyInstaller Runtime Hook for PyTorch DLL Loading.

PyTorch ships with bundled DLLs(c10.dll, torch_cpu.dll, etc.) that are
interdependent. When PyInstaller extracts the.exe to a temp dir, the DLLs
can't find each other unless their parent folder is on the system PATH.

This hook runs BEFORE any Python imports happen, ensuring PyTorch's lib/
directory is on PATH so Windows DLL resolution works correctly.
"""
import os 
import sys 


def _fix_torch_dll_path():
    """Prepend the torch lib directory to PATH so DLLs resolve correctly."""
    #sys._MEIPASS is the temp extraction folder PyInstaller uses at runtime
    if not hasattr(sys ,'_MEIPASS'):
        return #running from source — not needed

    meipass =sys._MEIPASS 

    #torch places its DLLs in <_MEIPASS>/torch/lib/
    torch_lib =os.path.join(meipass ,'torch','lib')
    if os.path.isdir(torch_lib ):
    #prepend so it takes priority over any system torch
        os.environ['PATH']=torch_lib +os.pathsep +os.environ.get('PATH','')

        #also add <_MEIPASS>/torch/bin/ (some builds use this layout)
    torch_bin =os.path.join(meipass ,'torch','bin')
    if os.path.isdir(torch_bin ):
        os.environ['PATH']=torch_bin +os.pathsep +os.environ.get('PATH','')

        #on Python 3.8+ Windows doesn't use PATH for DLL resolution by default
        #we must also call add_dll_directory() so the loader searches there
    if hasattr(os ,'add_dll_directory'):
        if os.path.isdir(torch_lib ):
            os.add_dll_directory(torch_lib )
        if os.path.isdir(torch_bin ):
            os.add_dll_directory(torch_bin )


_fix_torch_dll_path()
