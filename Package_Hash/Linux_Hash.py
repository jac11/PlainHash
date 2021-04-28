#!/usr/bin/env python3


import crypt
import bcrypt
import time
import argparse
import sys
import os
import re 
from Package_Hash.Banner import Banner
from Package_Hash.Hash_Crack import *


W='\033[0m'     
R='\033[31m'    
G='\033[0;32m'  
O='\33[37m'     
B='\033[34m'    
P='\033[35m'   
Y='\033[1;33m' 

class Linux_Hash:
     
        def __init__(self):
           
            global W
            global R
            global G
            global O
            global B
            global P
            global Y 
            
            self.control() 
            self.input_hash()                     
        def input_hash(self):
            if self.args.read:
                try:
                   self.path= os.path.abspath(self.args.read)
                   self.list= open(self.path)             
                   self.line_read =self.list.readline().rstrip() 
                   self.input_value = self.line_read
                   self.Hash_Linux()
                except FileNotFoundError:
                    print('[*] Hash File','{}'.format(self.path),' Not Found') 
                    exit()  
        def Hash_Linux(self):
           time.sleep(1)
           print()  
           print(B+'[*]'+W,R+'Hash-Identifier'+W)
           print(Y+"*"*20+W,'\n')
           time.sleep(1)                  
           if self.args.read  and '$1$' in self.input_value  :
               re_Hash_id   = str(re.findall('^([$]\w+[$])'   ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'')
               re_hash_salt = str(re.findall('(.[^$^]\w+[$])' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'') 
               hash_type =    str(re.findall('(...[^$^]\w+[$])' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'').rstrip()                          
               Hash = self.input_value.replace(hash_type,'')
               try:
                  self.path = os.path.abspath(self.args.wordlist)
                  self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                  self.line = self.list.read()            
                  passwords = self.line.split() 
               except FileNotFoundError :
                   print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                   exit()      
               print(B+'[*]'+W+R+' Hash Id   :'+W+Y+' MD5-based'+W+B+'crypt:[md5crypt] '+W)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash Salt :'+W+Y,re_hash_salt)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash      :'+W,Y+Hash+W)
               time.sleep(1)
               print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
               time.sleep(2)
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value+W )
               count = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type)
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+Y+'Same Hash Match : '+W,B+crypt_Hash+W)
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W)                                                           
                         break
                         exit()
                   print(B+'[*] '+W+R+'Try Password    : '+W,secrit);print(B+'[*] '+W+R+'Try Hash        : '+W,R+hash_type+crypt_Hash[len(hash_type):]+W)\
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)      
                   time.sleep(0.10)                           
                   sys.stdout.write('\x1b[1A')
                   sys.stdout.write('\x1b[2K')                                                       
                   sys.stdout.write('\x1b[1A')
                   sys.stdout.write('\x1b[2K')                            
                   sys.stdout.write('\x1b[1A')
                   sys.stdout.write('\x1b[2K')   
                   count +=1
               else:  
                   print (B+'\n[*] Password Not Found','\n')
                   print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                   exit()                                  
                                         
           elif self.args.read  and '$y$' in self.input_value :
               re_Hash_id   = str(re.findall('^([$]\w+[$])'   ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'')
               re_hash_salt = str(re.findall('(.[^$^]\w+[$])' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'') 
               hash_type =    str(re.findall('\S+\D+[$]' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'').rstrip()                         
               Hash = self.input_value.replace(hash_type,'')
               try:
                   self.path = os.path.abspath(self.args.wordlist)
                   self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                   self.line = self.list.read()            
                   passwords = self.line.split()  
               except FileNotFoundError :
                   print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                   exit()        
               print(B+'[*]'+W+R+' Hash Id   :'+W+Y+' bcrypt - Version: y '+W)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash Salt :'+W+Y,hash_type)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash      :'+W,Y+Hash+W)
               time.sleep(1)
               print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
               time.sleep(2)
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value[0:35],'\n','                   : ', self.input_value[36:] +W)
               count = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type)
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+R+ 'Same Hash Match : '+W,R+crypt_Hash[:35])\
                         ;print('                    : ',crypt_Hash[36:]+W) 
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W)                                                           
                         break
                         exit()
                   print(B+'[*] '+W+B+'Try Password    : '+W,P+secrit+W);print()\
                   ; print(B+'[*] '+W+R+'Try Hash        : ', R+hash_type+W+B+crypt_Hash[len(hash_type):40])\
                   ;print('                    : ',crypt_Hash[41:]+W)\
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)  
                               
                   
                   time.sleep(0.10)                           
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
               else:  
                   print (B+'\n[*] Password Not Found','\n')
                   print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                   exit() 
        
           elif self.args.read  and '$sha1$' in self.input_value :
               e_Hash_id   = str(re.findall('^([$]\w+[$])'   ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'')
               re_hash_salt = str(re.findall('^[$^]\S+[$]' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'') 
               hash_type =    str(re.findall('^[$^]\S+[$]',\
               self.input_value)).replace("[",'').replace("]",'').replace("'",'').rstrip()\
               .replace(',','').replace(' ','')                       
               Hash = self.input_value.replace(hash_type,'')
               try:
                  self.path = os.path.abspath(self.args.wordlist)
                  self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                  self.line = self.list.read()            
                  passwords = self.line.split()  
               except FileNotFoundError :
                   print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                   exit()           
               print(B+'[*]'+W+R+' Hash Id   :'+W+Y+' SHA1-based'+W+B+ ' crypt: '+W+R+'[sha1crypt] '+W)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash Salt :'+W+Y,hash_type)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash      :'+W,Y+Hash+W)
               time.sleep(1)
               print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
               time.sleep(2)
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value[0:35],'\n','                   : ', self.input_value[36:] +W)
               count = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type)
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+R+ 'Same Hash Match : '+W,R+crypt_Hash[:35])\
                         ;print('                    : ',crypt_Hash[36:]+W) 
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W)                                                           
                         break
                         exit()
                   print(B+'[*] '+W+B+'Try Password    : '+W,P+secrit+W);print()\
                   ; print(B+'[*] '+W+R+'Try Hash        : ', R+hash_type+W+B+crypt_Hash[len(hash_type):40])\
                   ;print('                    : ',crypt_Hash[41:]+W)\
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)  
                                                   
                   time.sleep(0.10)                           
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
               else:  
                   print (B+'\n[*] Password Not Found','\n')
                   print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                   exit() 
                 
           elif self.args.read  and '$5$' in self.input_value :
               re_Hash_id   = str(re.findall('^([$]\w+[$])'   ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'')
               re_hash_salt = str(re.findall('(.[^$^]\w+[$])' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'') 
               hash_type =    str(re.findall('^[$^]\S+[$]' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'').rstrip()                          
               Hash = self.input_value.replace(hash_type,'')
               try:
                  self.path = os.path.abspath(self.args.wordlist)
                  self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                  self.line = self.list.read()            
                  passwords = self.line.split()
               except FileNotFoundError :
                  print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                  exit()             
               print(B+'[*]'+W+R+' Hash Id   :'+W+Y+' SHA256-based'+W+B+ ' crypt: '+'W+R+[sha256crypt] '+W)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash Salt :'+W+Y,re_hash_salt)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash      :'+Y+Hash+W)
               time.sleep(1)
               print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
               time.sleep(2)
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value[0:52],'\n','                   : ', self.input_value[53:] +W)
               count = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type )                
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+R+ 'Same Hash Match : '+W,R+crypt_Hash[:52])\
                         ;print('                    : ',crypt_Hash[53:]+W,)  
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W)                                                           
                         break
                         exit()
                   print(B+'[*] '+W+B+'Try Password    : '+W,P+secrit+W);print()\
                   ;print(B+'[*] '+W+R+'Try Hash        : ',                  
                   R+hash_type+W+B+crypt_Hash[len(hash_type):52])\
                   ;print('                    : ',crypt_Hash[53:]+W)\
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)      
                   time.sleep(0.10)                           
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
               else:  
                   print (B+'\n[*] Password Not Found','\n')
                   print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                   exit() 
                                                                              
               
           elif self.args.read  and '$6$' in self.input_value :
               re_Hash_id   = str(re.findall('^([$]\w+[$])'   ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'')
               re_hash_salt = str(re.findall('(.[^$^]\w+[$])' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'') 
               hash_type =    str(re.findall('^[$^]\S+[$]' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'').rstrip()                          
               Hash = self.input_value.replace(hash_type,'')
               try:
                  self.path = os.path.abspath(self.args.wordlist)
                  self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                  self.line = self.list.read()            
                  passwords = self.line.split()  
               except FileNotFoundError :
                   print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                   exit()           
               print(B+'[*]'+W+R+' Hash Id   :'+W+Y+' SHA512-based'+W+B+ ' crypt: '+W+R+'[sha512crypt] '+W)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash Salt :'+W+Y,re_hash_salt)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash      :'+W,Y+Hash [0:40],'\n','             :',Hash[41:]+W)
               time.sleep(1)
               print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
               time.sleep(2)
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value[0:52],'\n','                   : ', self.input_value[53:] +W)
               count = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type )                
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+R+ 'Same Hash Match : '+W,R+crypt_Hash[:52])\
                         ;print('                    : ',crypt_Hash[53:]+W,'\n')  
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W)                                                           
                         break
                         exit()
                   print(B+'[*] '+W+B+'Try Password    : '+W,P+secrit+W);print()\
                   ; print(B+'[*] '+W+R+'Try Hash        : ',R+hash_type+W+B+crypt_Hash[len(hash_type):52])\
                   ;print('                    : ',crypt_Hash[53:]+W) \
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)                                           
                   time.sleep(0.10)                           
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
               else:  
                   print (B+'\n[*] Password Not Found','\n')
                   print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                   exit() 
                                                                                                                              
        def control(self):
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]")      
           parser.add_argument("-w","--wordlist" , metavar='' , action=None ,required=True,help ="wordlist of passwords") 
           parser.add_argument("-r","--read" , metavar='' , action=None ,help ="read the hash from file input" ) 
           self.args = parser.parse_args()     
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help()         
              exit()                   
        
if __name__ == '__main__':
     Linux_Hash()
