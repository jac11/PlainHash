#!/usr/bin/env python3

import subprocess
from subprocess import PIPE 
from Package_Hash.Hash_Crack import *
from Package_Hash.Linux_Hash import *
Check_Import ="pip show pycryptodome"
Check_Import = subprocess.call(Check_Import,shell=True,stderr=subprocess.PIPE,stdout=PIPE) 
if Check_Import == 0:
    pass
else:
    os.system("pip3 install --upgrade requests >/dev/null 2>&1")
    Process = "pip install pycryptodome"  
    subprocess.call(Process,shell=True,stderr=subprocess.PIPE,stdout=PIPE)
class Start :
   def __init__(self): 
       run = Plain_Hash()
if __name__=='__main__':
   Start()    
