#!/usr/bin/env python3

import hashlib
import time
import argparse
import sys
import os


W='\033[0m'     
R='\033[31m'    
G='\033[0;32m'  
O='\33[37m'     
B='\033[34m'    
P= '\033[35m'   
Y="\033[1;33m" 
  

class Hash_Creck :

     
     def __init__(self):
         
         global W
         global R
         global G
         global O
         global B
         global P
         global Y   
         
         self.banner    = R+'''
                
  , _ , __             
 /|/  \| |       o         /|   |           | |     
  |___/| |  __,      _  _   |___|  __,   ,  | |    
  |    |/  /  |  |  / |/ |  |   |\/  |  / \_|/ \   
  |    |__/\_/|_/|_/  |  |_/|   |/\_/|_/ \/ |   |_/
                                   by:jacstory
                                                   
 '''+W                                               
         print (self.banner)                                          
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
                self.line_read =self.list.readline().rstrip() 
                self.input_value = self.line_read
                self.hash_id()
            elif self.args.hash:
                self.input_value = sys.argv[2] 
                self.hash_id()
     def hash_id(self)  :
         
       # try:             
                if len(self.input_value) == len(self.md5_hash) :
                     time.sleep(1)
                     print()  
                     print(B+'[*]'+W,R+'IDENTYFIR HASH'+W)
                     print(Y+"*"*20+W,'\n')
                     time.sleep(1)
                     print(B+'[*]'+W+R+'Hash  ID  : MD5   |', ' [*] len  :'+W,R+str(len(self.md5_hash))+W,'\n')
                     time.sleep(2)
                     print((B+'*'*30+W),'\n',B+'[*]'+W+R+'HASH CRACK START'+W,'\n',(B+'-'*20+W),'\n')
                     time.sleep(2)
                     print(B+'[*]'+W+Y+'Orgenal Hash    : '+W,O+self.input_value+W )
                     if self.args.hash or self.args.read :
                        self.path = os.path.abspath(self.args.wordlist)
                        self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                        self.line = self.list.read()            
                        passwords = self.line.split()
                        count = 0
                        for secrit in passwords :
                            hash_password = hashlib.md5(secrit.encode()).hexdigest()
                            if hash_password == self.input_value : 
                               print(B+'[*]'+W+Y+'Same Hash Match : '+W,B+hash_password+W)
                               print (B+'[*]'+W+R+'Password Found  : '+W,P+secrit+W)
                               print(B+'[*]'+W+Y+'Password Count  : '+W,R+str(count)+W)                                                           
                               break
                            print(B+'[*]'+W+R+'Try Password    : '+W,secrit);print(B+'[*]'+W+R+'Try Hash        : '+W,R+hash_password+W)\
                            ;print(B+'[*]'+W+B+'Password Count  : '+W,R+str(count)+W)
                           
                            time.sleep(0.10)                           
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                       
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                            
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')   
                            count +=1                         
                elif len(self.input_value) == len(self.SHA_1) :
                     time.sleep(1)  
                     print()  
                     print(B+'[*]'+W,R+'IDENTYFIR HASH'+W)
                     print(Y+"*"*20+W,'\n')
                     time.sleep(1)
                     print(B+'[*]'+W+R+'Hash  ID  : SHA1   |', ' [*] len  :'+W,R+str(len(self.SHA_1))+W,'\n')
                     print((B+'*'*30+W),'\n',B+'[*]'+W+R+'HASH CRACK START','\n',(B+'-'*20+W),'\n')
                     time.sleep(2)
                     print(B+'[*]'+W+Y+'Orgenal Hash    : '+W,O+self.input_value+W )
                     if self.args.hash or self.args.read:
                        self.path = os.path.abspath(self.args.wordlist)
                        self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                        self.line = self.list.read()            
                        passwords = self.line.split()
                        count = 0
                        for secrit in passwords :
                            hash_password = hashlib.sha1(secrit.encode()).hexdigest()
                            if hash_password == self.input_value : 
                               print(B+'[*]'+W+Y+'Same Hash Match : '+W,B+hash_password+W)
                               print (B+'[*]'+W+R+'Password Found  : '+W,P+secrit+W)
                               print(B+'[*]'+W+Y+'Password Count  : '+W,R+str(count)+W)                                                                
                               break
                            print(B+'[*]'+W+R+'Try Password    : '+W,R+secrit+W);print(B+'[*]'+W+R+'Try Hash        : '+W,B+hash_password+W)\
                            ;print(B+'[*]'+W+B+'Password Count  : '+W,R+str(count)+W)
                            time.sleep(0.15)                           
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')                                                     
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')
                            sys.stdout.write('\x1b[1A')
                            sys.stdout.write('\x1b[2K')
                            count +=1               
                elif len(self.input_value) == len(self.SHA3_384 ) :
                     print()  
                     print(B+'[*]'+W+R+'IDENTYFIR HASH'+W)
                     print(Y+"*"*20+W,'\n')
                     time.sleep(1)
                     print(B+'[*]'+W+R+'Hash  ID  : SHA3_384    |', ' [*] len  :'+W,R+str(len(self.SHA3_384))+W,'\n')
                     print((B+'*'*30+W),'\n',B+'[*]'+W+R+'HASH CRACK START','\n',(B+'-'*20+W),'\n')
                     time.sleep(2)
                     print(B+'[*]'+W+Y+'Orgenal Hash       : '+W,O+self.input_value[:50],'\n','                     : ', self.input_value[51:] +W)
                     print()
                     if self.args.hash or self.args.read:
                        self.path = os.path.abspath(self.args.wordlist)
                        self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                        self.line = self.list.read()            
                        passwords = self.line.split()
                        count = 0  
                        for secrit in passwords :
                            hash_password = hashlib.sha3_384(secrit.encode()).hexdigest()
                            if hash_password == self.input_value : 
                               print(B+'[*]'+W+Y+'Same Hash Match    : '+W,B+hash_password[:50])\
                               ;print('                      : ',hash_password[51:]+W)
                               print (B+'[*]'+W+R+'Password Found     : '+W,P+secrit+W)
                               print(B+'[*]'+W+Y+'Password Count     : '+W,R+str(count)+W)                                                          
                               break
                            print(B+'[*]'+W+R+'Try Password       : '+W,R+secrit+W);print(); print(B+'[*]'+W+R+'Try Hash           : '+W,\
                            B+hash_password[:50]);print('                      : ',hash_password[51:]+W)\
                            ;print(B+'[*]'+W+R+'Password Count     : '+W,Y+str(count)+W)
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
                elif len(self.input_value)== len(self.SHA_256) and len(self.input_value)== len(self.SHA_3_256 ) \
                and len(self.input_value)== len(self.BLAKE2c):
                     time.sleep(1)  
                     print()  
                     print(B+'[*]'+W,R+'IDENTYFIR HASH'+W)
                     print(Y+"*"*20+W,'\n')
                     time.sleep(1)
                     print (B+'[*]'+W+R+'Hash  ID  : SHA256   |', ' [*] len  :'+W+R+str(len(self.SHA_256))+W)
                     time.sleep(1)
                     print (B+'[*]'+W+Y+'Hash  ID  : SHA3_256 |',' [*] len  :'+W+Y+str(len(self.SHA_3_256))+W)
                     time.sleep(1)
                     print (B+'[*]'+W+B+'Hash  ID  : BLAKE2S  |' ,' [*] len  :'+W+B+str(len(self.BLAKE2c ))+W) 
                     print((B+'*'*30+W),'\n',B+'[*]'+W+R+'HASH CRACK START','\n',(B+'-'*20+W),'\n')
                     time.sleep(2)
                     print(B+'[*]'+W+B+'Orgenal Hash       : '+W,O+self.input_value+W ) 
                     if self.args.hash or self.args.read:
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
                                print(B+'[*]'+W+R+'Same Hash Match    : ',hash_password+W)  
                                print (B+'[*]'+W+B+'Hash ID            :'+W+R+'  sha256 '+W) 
                                print (B+'[*]'+W+R+'Password Found     : '+W,P+secrit+W) 
                                print(B+'[*]'+W+B+'Password Count     : '+W,P+str(count)+W)
                                break                              
                            elif hash_password1 ==self.input_value :
                                print(B+'[*]'+W+Y+'Same Hash Match    : '+W,Y+hash_password1+W)  
                                print (B+'[*]'+W+B+'Hash ID            :'+W+R+'  SHA3_256 '+W) 
                                print (B+'[*]'+W+R+'Password Found     : '+W,P+secrit+W) 
                                print(B+'[*]'+W+B+'Password Count     : '+W,P+str(count)+W)                              
                                break     
                            elif hash_password2 ==self.input_value:
                                print(B+'[*]'+W+B+'Same Hash Match    : ',hash_password2+W)  
                                print (B+'[*]'+W+Y+'Hash ID            :'+W+R+'  BLAKE2S '+W) 
                                print (B+'[*]'+W+R+'Password Found     : '+W,P+secrit+W) 
                                print(B+'[*]'+W+B+'Password Count     : '+W,P+str(count)+W)
                                break     
                                                                                          
                            print(B+'[*]'+W+B+'Try Password       : '+W,P+secrit+W);print(B+'[*]'+W+R+'Try Hash sha256    : '+W,R+hash_password+W)\
                            ;print(B+'[*]'+W+Y+'Try Hash sha3_256  : '+W,Y+hash_password1+W)\
                            ;print(B+'[*]'+W+B+'Try Hash blake2s   : '+W,B+hash_password2+W);print(B+'[*]'+W+R+'Password Count     : '+W,P+str(count)+W)
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
                     print(B+'[*]'+W,R+'IDENTYFIR HASH'+W)
                     print(Y+"*"*20+W,'\n')
                     time.sleep(1)
                     print (B+'[*]'+W+R'Hash  ID  : SHA3_512    |', ' [*] len  :',len(self.SHA_3_512))
                     time.sleep(1)
                     print (B+'[*]'+W+R'Hash  ID  : BLAKE2b     |',' [*] len  :',len(self.BLAKE2b))
                     time.sleep(1)
                     print (B+'[*]'+W+R'Hash  ID  : SHA512      |' ,' [*] len  :',len(self.SHA_512 ))
                     print((B+'*'*30+W),'\n',B+'[*]'+W+R'HASH CRACK START','\n',(B+'-'*20+W),'\n')
                     time.sleep(2)
                     print(B+'[*]'+W+R'Orgenal Hash       : ',self.input_value[0:63],'\n','                      : ', self.input_value[64:128] )
                     print()
                     
                     if self.args.hash or self.args.read:
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
                                print(B+'[*]'+W+R'Same Hash Match    : ',hash_password[:63])\
                                ;print('                       : ',hash_password[64:],'\n')  
                                print (B+'[*]'+W+R'Hash ID            :  SHA3_512 ') 
                                print (B+'[*]'+W+R'Password Found     : ',secrit) 
                                print(B+'[*]'+W+R'Password Count     : ',str(count))
                                break                              
                            elif hash_password1 ==self.input_value :
                                print(B+'[*]'+W+R'Same Hash Match    : ',hash_password1[:63])\
                                ;print('                       : ',hash_password1[64:] ,'\n') 
                                print (B+'[*]'+W+R'Hash ID            :  BLAKE2b ') 
                                print (B+'[*]'+W+R'Password Found     : ',secrit) 
                                print(B+'[*]'+W+R'Password Count     : ',str(count))
                                break     
                            elif hash_password2 ==self.input_value:
                                print(B+'[*]'+W+R'Same Hash Match    : ',hash_password2[:63])\
                                ;print('                       : ',hash_password2[64:] ,'\n')
                                print (B+'[*]'+W+R'Hash ID            :  SHA512 ') 
                                print (B+'[*]'+W+R'Password Found     : ',secrit) 
                                print(B+'[*]'+W+R'Password Count     : ',str(count))
                                break     
                                        
                            print(B+'[*]'+W+R'Try Password       : ',secrit);print(); print(B+'[*]'+W+R'Try Hash sha3_512  : ',\
                            hash_password[:63]);print('                       : ',hash_password[64:])\
                            ;print()\
                            ;print(B+'[*]'+W+R'Try Hash blake2b   : ',hash_password1[:63])\
                            ;print('                       : ',hash_password1[64:])\
                            ;print()\
                            ;print(B+'[*]'+W+R'Try Hash sha512    : ',hash_password2[:63])\
                            ;print('                       : ',hash_password2[64:])\
                            ;print()\
                            ;print(B+'[*]'+W+R'Password Count     : ',str(count))
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
                     print(B+'[*]'+W,R+'IDENTYFIR HASH'+W)
                     print(Y+"*"*20+W,'\n')
                     time.sleep(1)
                     print (B+'[*]'+W+R+'Hash  ID  : SHA3_224  |', ' [*] len  :',len(self.SHA3_224))
                     time.sleep(1)
                     print (B+'[*]'+W+R'Hash  ID  : SHA224    |',' [*] len  :',len(self.SHA_224),'\n') 
                     print((B+'*'*30+W),'\n',B+'[*]'+W+R'HASH CRACK START','\n',(B+'-'*20+W),'\n')
                     time.sleep(2)
                     print(B+'[*]'+W+R'Orgenal Hash       : ',self.input_value )  
                     if self.args.hash or self.args.read:
                        self.path = os.path.abspath(self.args.wordlist)
                        self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                        self.line = self.list.read()            
                        passwords = self.line.split()
                        count = 0  
                        for secrit in passwords :
                            hash_password = hashlib.sha3_224(secrit.encode()).hexdigest()
                            hash_password1 = hashlib.sha224(secrit.encode()).hexdigest()
                            if hash_password == self.input_value :
                                print(B+'[*]'+W+R'Same Hash Match    : ',hash_password)  
                                print (B+'[*]'+W+R'Hash ID            :  SHA3_224 ') 
                                print (B+'[*]'+W+R'Password Found     : ',secrit) 
                                print(B+'[*]'+W+R'Password Count     : ',str(count))
                                break                              
                            elif hash_password1 ==self.input_value :
                                print(B+'[*]'+W+R'Same Hash Match    : ',hash_password1)  
                                print (B+'[*]'+W+R'Hash ID            :  SHA224  ') 
                                print (B+'[*]'+W+R'Password Found     : ',secrit) 
                                print(B+'[*]'+W+R'Password Count     : ',str(count))
                                break     

                            print(B+'[*]'+W+R'Try Password       : ',secrit); print(B+'[*]'+W+R'Try Hash sha3_224  : ',hash_password)\
                            ;print(B+'[*]'+W+R'Try Hash sha224    : ',hash_password1);print(B+'[*]'+W+R'Password Count     : ',str(count))
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
      #  except Exception :
       #       print('input hash Not in our databasess ')
        #      exit()   
     def control(self):
    
        parser = argparse.ArgumentParser( description="Usage: [OPtion] [arguments] [OPtion] [arguments]  Example: ./PlainHash.py -H dfd5f9139a820075df69d7895015360b76d0360f3d4b77a845689614 -w wordlist ")
        parser.add_argument("-H",'--hash' , metavar='' , action=None  ,help ="Hash string ") 
        parser.add_argument("-w","--wordlist" , metavar='' , action=None ,required=True,help ="wordlist of paaswords") 
        parser.add_argument("-r","--read" , metavar='' , action=None ,help ="read the hash from file input") 
        self.args = parser.parse_args()
     
        if len(sys.argv)!=1 :
            pass
        else:
            print(self.banner)
            parser.print_help()           
            exit()
     

if __name__ == '__main__':
   Hash_Creck()

