#!/usr/bin/env python3

import hashlib
import time
import argparse
import sys
import os

class Hash_Creck :

     
     def __init__(self):
         self.md5_hash  = 'cfcd208495d565ef66e7dff9f98764da'
         self.SHA_1     = 'b6589fc6ab0dc82cf12099d1c2d40ab994e8410c'
         self.SHA3_384  = '17c0608360f9652153b4bf29611b146bbb7ed3336c33d944c8cf7637ffe8ff440b3b0b67a127a183a5d7e2d978f544c5'
         self.SHA_256   = '5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9'        
         self.SHA_3_256 = 'f9e2eaaa42d9fe9e558a9b8ef1bf366f190aacaa83bad2641ee106e9041096e4'
         self.BLAKE2c   = '652e530edee5893b576f72b875ea1c918e85e29d859e7e3fa78b623d8abca3de'
         self.SHA_3_512 = '2d44da53f305ab94b6365837b9803627ab098c41a6013694f9b468bccb9c13e95b3900365eb58924de7158a54467e984efcfdabdbcc9af9a940d49c51455b04c'
         self.BLAKE2b   = 'e9f11462495399c0b8d0d8ec7128df9c0d7269cda23531a352b174bd29c3b6318a55d3508cb70dad9aaa590185ba0fef4fab46febd46874a103739c10d60ebc7'
         self.SHA_512   = '31bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025f00bf0ea68dbf3f3a5436ca63b53bf7bf80ad8d5de7d8359d0b7fed9dbc3ab99'   
         self.SHA3_224  = 'a823c3f51659da24d9a61254e9f61c39a4c8f11fd65820542403dd1c'
         self.SHA_224   = 'dfd5f9139a820075df69d7895015360b76d0360f3d4b77a845689614'
         self.control()
         self.input_hash()
     def input_hash(self):
            if self.args.read:
                self.path= os.path.abspath(self.args.read)
                self.list= open(self.path)             
                self.line =self.list.readline().rstrip() 
                self.input_value = self.line
                self.hash_id()
            elif self.args.hash:
                self.input_value = sys.argv[2] 
                self.hash_id()
     def hash_id(self)  :
         
        #  try:             
                if len(self.input_value) == len(self.md5_hash) :
                     time.sleep(1)
                     print()  
                     print('[*] IDENTYFIR HASH')
                     print("*"*20,'\n')
                     time.sleep(1)
                     print('[*] Hash  ID  : MD5   |', ' [*] len  :',len(self.md5_hash),'\n')
                     time.sleep(2)
                     print(('*'*30),'\n','[*] HASH CRACK START','\n',('-'*20),'\n')
                     time.sleep(2)
                     print('[*] Orgenal Hash    : ',self.input_value )
                     if self.args.hash:
                        self.path = os.path.abspath(self.args.wordlist)
                        self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                        self.line = self.list.read()            
                        passwords = self.line.split()
                        count = 0
                        for secrit in passwords :
                            hash_password = hashlib.md5(secrit.encode()).hexdigest()
                            if hash_password == self.input_value : 
                               print('[*] Same Hash Match : ',hash_password)
                               print ('[*] Password Found  : ',secrit)
                               print('[*] Password Count  : ',str(count))                                                           
                               break
                            print('[*] Try Password    : ',secrit);print('[*] Try Hash        : ',hash_password)\
                            ;print('[*] Password Count  : ',str(count))
                           
                            time.sleep(0.10)                           
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                       
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                            
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')   
                            count +=1                         
                elif len(self.input_value)	== len(self.SHA_1) :
                     time.sleep(1)  
                     print()  
                     print('[*] IDENTYFIR HASH')
                     print("*"*20,'\n')
                     time.sleep(1)
                     print ('[*] Hash  ID  : SHA1   |', ' [*] len  :',len(self.SHA_1),'\n')
                     print(('*'*30),'\n','[*] HASH CRACK START','\n',('-'*20),'\n')
                     time.sleep(2)
                     print('[*] Orgenal Hash    : ',self.input_value )
                     if self.args.hash:
                        self.path = os.path.abspath(self.args.wordlist)
                        self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                        self.line = self.list.read()            
                        passwords = self.line.split()
                        count = 0
                        for secrit in passwords :
                            hash_password = hashlib.sha1(secrit.encode()).hexdigest()
                            if hash_password == self.input_value : 
                               print('[*] Same Hash Match : ',hash_password)
                               print ('[*] Password Found  : ',secrit)
                               print('[*] Password Count  : ',str(count))                                                           
                               break
                            print('[*] Try Password    : ',secrit);print('[*] Try Hash        : ',hash_password)\
                            ;print('[*] Password Count  : ',str(count))
                            time.sleep(0.15)                           
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                     
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')
                            count +=1               
                elif len(self.input_value)	== len(self.SHA3_384 ) :
                     print()  
                     print('[*] IDENTYFIR HASH')
                     print("*"*20,'\n')
                     time.sleep(1)
                     print ('[*] Hash  ID  : SHA3_384    |', ' [*] len  :',len(self.SHA3_384),'\n') 
                     print(('*'*30),'\n','[*] HASH CRACK START','\n',('-'*20),'\n')
                     time.sleep(2)
                     print('[*] Orgenal Hash       : ',self.input_value[:50],'\n','                      : ', self.input_value[51:] )
                     print()
                     if self.args.hash:
                        self.path = os.path.abspath(self.args.wordlist)
                        self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                        self.line = self.list.read()            
                        passwords = self.line.split()
                        count = 0  
                        for secrit in passwords :
                            hash_password = hashlib.sha3_384(secrit.encode()).hexdigest()
                            if hash_password == self.input_value : 
                               print('[*] Same Hash Match    : ',hash_password[:50])\
                               ;print('                       : ',hash_password[51:])
                               print ('[*] Password Found     : ',secrit)
                               print('[*] Password Count     : ',str(count))                                                          
                               break
                            print('[*] Try Password       : ',secrit);print(); print('[*] Try Hash sha3_512  : ',\
                            hash_password[:50]);print('                       : ',hash_password[51:])\
                            ;print('[*] Password Count     : ',str(count))
                            time.sleep(0.15)                           
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                                                  
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                    
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K') 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')
                            count +=1         
                elif len(self.input_value)	== len(self.SHA_256) and len(self.input_value)== len(self.SHA_3_256 ) \
                and len(self.input_value)== len(self.BLAKE2c):
                     time.sleep(1)  
                     print()  
                     print('[*] IDENTYFIR HASH')
                     print("*"*20,'\n')
                     time.sleep(1)
                     print ('[*] Hash  ID  : SHA256   |', ' [*] len  :',len(self.SHA_256))
                     time.sleep(1)
                     print ('[*] Hash  ID  : SHA3_256 |',' [*] len  :',len(self.SHA_3_256))
                     time.sleep(1)
                     print ('[*] Hash  ID  : BLAKE2S  |' ,' [*] len  :',len(self.BLAKE2c )) 
                     print(('*'*30),'\n','[*] HASH CRACK START','\n',('-'*20),'\n')
                     time.sleep(2)
                     print('[*] Orgenal Hash       : ',self.input_value ) 
                     if self.args.hash:
                        self.path = os.path.abspath(self.args.wordlist)
                        self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                        self.line = self.list.read()            
                        passwords = self.line.split()
                        count = 0  
                        for secrit in passwords :
                            hash_password  = hashlib.sha256(secrit.encode()).hexdigest()
                            hash_password1 = hashlib.sha3_256(secrit.encode()).hexdigest()
                            hash_password2 = hashlib.blake2s(secrit.encode()).hexdigest()
                            if hash_password == self.input_value :
                                print('[*] Same Hash Match    : ',hash_password)  
                                print ('[*] Hash ID            :  sha256 ') 
                                print ('[*] Password Found     : ',secrit) 
                                print('[*] Password Count     : ',str(count))
                                break                              
                            elif hash_password1 ==self.input_value :
                                print('[*] Same Hash Match    : ',hash_password1)  
                                print ('[*] Hash ID            :  sha3_256 ') 
                                print ('[*] Password Found     : ',secrit) 
                                print('[*] Password Count     : ',str(count))
                                break     
                            elif hash_password2 ==self.input_value:
                                print('[*] Same Hash Match    : ',hash_password2)  
                                print ('[*] Hash ID            :  blake2s ') 
                                print ('[*] Password Found     : ',secrit) 
                                print('[*] Password Count     : ',str(count))
                                break     
                                                                                          
                            print('[*] Try Password       : ',secrit); print('[*] Try Hash sha256    : ',hash_password)\
                            ;print('[*] Try Hash sha3_256  : ',hash_password1)\
                            ;print('[*] Try Hash blake2s   : ',hash_password2);print('[*] Password Count     : ',str(count))
                            time.sleep(0.15)                           
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                                                   
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                                                                           
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K') 
                            count +=1         
                                
                elif len(self.input_value)	== len(self.SHA_3_512) and len(self.input_value)==len(self.BLAKE2b)\
                and len(self.input_value)== len (self.SHA_512):
                     time.sleep(1)  
                     print()  
                     print('[*] IDENTYFIR HASH')
                     print("*"*20,'\n')
                     time.sleep(1)
                     print ('[*] Hash  ID  : SHA3_512    |', ' [*] len  :',len(self.SHA_3_512))
                     time.sleep(1)
                     print ('[*] Hash  ID  : BLAKE2b     |',' [*] len  :',len(self.BLAKE2b))
                     time.sleep(1)
                     print ('[*] Hash  ID  : SHA512      |' ,' [*] len  :',len(self.SHA_512 ))
                     print(('*'*30),'\n','[*] HASH CRACK START','\n',('-'*20),'\n')
                     time.sleep(2)
                     print('[*] Orgenal Hash       : ',self.input_value[0:63],'\n','                      : ', self.input_value[64:128] )
                     print()
                     
                     if self.args.hash:
                        self.path = os.path.abspath(self.args.wordlist)
                        self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                        self.line = self.list.read()            
                        passwords = self.line.split()                        
                        count = 0  
                        for secrit in passwords :
                            hash_password  = hashlib.sha3_512(secrit.encode()).hexdigest()
                            hash_password1 = hashlib.blake2b(secrit.encode()).hexdigest()
                            hash_password2 = hashlib.sha512(secrit.encode()).hexdigest()
                            if hash_password == self.input_value :
                                print('[*] Same Hash Match    : ',hash_password[:63])\
                                ;print('                       : ',hash_password[64:],'\n')  
                                print ('[*] Hash ID            :  SHA3_512 ') 
                                print ('[*] Password Found     : ',secrit) 
                                print('[*] Password Count     : ',str(count))
                                break                              
                            elif hash_password1 ==self.input_value :
                                print('[*] Same Hash Match    : ',hash_password1[:63])\
                                ;print('                       : ',hash_password1[64:] ,'\n') 
                                print ('[*] Hash ID            :  BLAKE2b ') 
                                print ('[*] Password Found     : ',secrit) 
                                print('[*] Password Count     : ',str(count))
                                break     
                            elif hash_password2 ==self.input_value:
                                print('[*] Same Hash Match    : ',hash_password2[:63])\
                                ;print('                       : ',hash_password2[64:] ,'\n')
                                print ('[*] Hash ID            :  SHA512 ') 
                                print ('[*] Password Found     : ',secrit) 
                                print('[*] Password Count     : ',str(count))
                                break     
                                        
                            print('[*] Try Password       : ',secrit);print(); print('[*] Try Hash sha3_512  : ',\
                            hash_password[:63]);print('                       : ',hash_password[64:])\
                            ;print()\
                            ;print('[*] Try Hash blake2b   : ',hash_password1[:63])\
                            ;print('                       : ',hash_password1[64:])\
                            ;print()\
                            ;print('[*] Try Hash sha512    : ',hash_password2[:63])\
                            ;print('                       : ',hash_password2[64:])\
                            ;print()\
                            ;print('[*] Password Count     : ',str(count))
                            time.sleep(0.15)                           
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                                                   
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                                                                           
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K') 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')   
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K') 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K') 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K') 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K') 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')   
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')   
                            count +=1         
                elif len(self.input_value)	== len(self.SHA3_224) and len(self.input_value)==len(self.SHA_224):             	
                     time.sleep(1)  
                     print()  
                     print('[*] IDENTYFIR HASH')
                     print("*"*20,'\n')
                     time.sleep(1)
                     print ('[*] Hash  ID  : SHA3_224  |', ' [*] len  :',len(self.SHA3_224))
                     time.sleep(1)
                     print ('[*] Hash  ID  : SHA224    |',' [*] len  :',len(self.SHA_224),'\n') 
                     print(('*'*30),'\n','[*] HASH CRACK START','\n',('-'*20),'\n')
                     time.sleep(2)
                     print('[*] Orgenal Hash       : ',self.input_value )  
                     if self.args.hash:
                        self.path = os.path.abspath(self.args.wordlist)
                        self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                        self.line = self.list.read()            
                        passwords = self.line.split()
                        count = 0  
                        for secrit in passwords :
                            hash_password = hashlib.sha3_224(secrit.encode()).hexdigest()
                            hash_password1 = hashlib.sha224(secrit.encode()).hexdigest()
                            if hash_password == self.input_value :
                                print('[*] Same Hash Match    : ',hash_password)  
                                print ('[*] Hash ID            :  SHA3_224 ') 
                                print ('[*] Password Found     : ',secrit) 
                                print('[*] Password Count     : ',str(count))
                                break                              
                            elif hash_password1 ==self.input_value :
                                print('[*] Same Hash Match    : ',hash_password1)  
                                print ('[*] Hash ID            :  SHA224  ') 
                                print ('[*] Password Found     : ',secrit) 
                                print('[*] Password Count     : ',str(count))
                                break     

                            print('[*] Try Password       : ',secrit); print('[*] Try Hash sha3_224  : ',hash_password)\
                            ;print('[*] Try Hash sha224    : ',hash_password1);print('[*] Password Count     : ',str(count))
                            time.sleep(0.15)                           
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                                                   
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                 
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                                                                           
                            count +=1                   	
                           
                else:
                    time.sleep(1)  
                    print('\n[*] IDENTYFIR HASH\n',("*"*30),'\n')
                    print('input hash Not in our databasess ')
                    exit()        
       #   except Exception :
        #      print('input hash Not in our databasess ')
         #     exit()   
     def control(self):
    
        parser = argparse.ArgumentParser( description="Usage: [OPtion] [arguments] [OPtion] [arguments]  Example: ./webshop.py --URL https://www.site.com/ -o outbut ")
        parser.add_argument("-H",'--hash' , metavar='' , action=None  ,help ="Hash string ") 
        parser.add_argument("-w","--wordlist" , metavar='' , action=None ,required=True,help ="wordlist of paaswords") 
        parser.add_argument("-r","--read" , metavar='' , action=None ,help ="read the hash from file input") 
        self.args = parser.parse_args()
     
        if len(sys.argv)!=1 :
            pass
        else:
            parser.print_help()
            exit()
     

if __name__ == '__main__':
   Hash_Creck()



