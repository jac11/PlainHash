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
            if self.args.color  and 'off' in sys.argv:
                W=''     
                R=''    
                G=''  
                O=''     
                B=''    
                P=''   
                Y=''
            else:
                 if self.args.color  and 'off' not in  sys.argv :
                   print (P+'[*] error: argument -c/--color: expected argument off '+W)
                   exit() 
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
               print(B+'[*]'+W+R+' Hash Id   :'+W+Y+' MD5-based'+W+B+' crypt:[md5crypt] '+W)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash Salt :'+W+Y,re_hash_salt)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash      :'+W,Y+Hash+W)
               time.sleep(1)
               print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
               time.sleep(2)
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value+W )
               count  = 0                            
               second = 0    
               minute = 0    
               hours  = 0   
               count1 = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type)
                   if (count1 == 10): 
                       count1 =0                                                 
                       second+=1                                    
                   if(second == 60):    
                       second = 0    
                       minute+=1    
                   if(minute == 60):    
                       minute = 0    
                       hour+=1;
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+Y+'Same Hash Match : '+W,R+crypt_Hash+W)
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W) 
                         print(B+'[*] '+W+P+'Time        '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                         print('         ',B+('='*25)+W)                                                          
                         break
                         exit()
                   print(B+'[*] '+W+R+'Try Password    : '+W,P+secrit+W);print(B+'[*] '+W+R+'Try Hash        : '+W,Y+hash_type+W+B+crypt_Hash[len(hash_type):]+W)\
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)\
                   ;print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                   ;print('        ',B+('='*25)+W)    
                   time.sleep(0.1)                              
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
                   count  +=1
                   count1 +=1
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
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value[0:35],'\n','                   : ', self.input_value[35:] +W)
               count  = 0                            
               second = 0    
               minute = 0    
               hours  = 0   
               count1 = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type)
                   if (count1 == 8): 
                       count1 =0                                                 
                       second+=1                                    
                   if(second == 60):    
                       second = 0    
                       minute+=1    
                   if(minute == 60):    
                       minute = 0    
                       hour+=1;
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+R+ 'Same Hash Match : '+W,R+crypt_Hash[:35])\
                         ;print('                    : ',crypt_Hash[35:]+W) 
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W) 
                         print(B+'[*] '+W+P+'Time        '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                         print('         ',B+('='*25)+W)                                                          
                         break
                         exit()
                   print(B+'[*] '+W+B+'Try Password    : '+W,P+secrit+W);print()\
                   ; print(B+'[*] '+W+R+'Try Hash        : ', R+hash_type+W+B+crypt_Hash[len(hash_type):40])\
                   ;print('                    : ',crypt_Hash[40:]+W)\
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)\
                   ;print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                   ;print('        ',B+('='*25)+W)     
                   time.sleep(0.1)                                                       
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
                   count  +=1
                   count1 +=1
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
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value[0:35],'\n','                   : ', self.input_value[35:] +W)
               count  = 0                            
               second = 0    
               minute = 0    
               hours  = 0   
               count1 = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type)
                   if (count1 == 22): 
                       count1 =0                                                 
                       second+=1                                    
                   if(second == 60):    
                       second = 0    
                       minute+=1    
                   if(minute == 60):    
                       minute = 0    
                       hour+=1;
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+R+ 'Same Hash Match : '+W,R+crypt_Hash[:35])\
                         ;print('                    : ',crypt_Hash[35:]+W) 
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W)   
                         print(B+'[*] '+W+P+'Time        '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                         print('         ',B+('='*25)+W)                                                        
                         break
                         exit()
                   print(B+'[*] '+W+B+'Try Password    : '+W,P+secrit+W);print()\
                   ; print(B+'[*] '+W+R+'Try Hash        : ', R+hash_type+W+B+crypt_Hash[len(hash_type):40])\
                   ;print('                    : ',crypt_Hash[40:]+W)\
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)\
                   ;print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                   ;print('        ',B+('='*25)+W)     
                   time.sleep(0)                         
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
                   count  +=1
                   count1 +=1
               else:  
                   print (B+'\n[*] Password Not Found','\n')
                   print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                   exit() 
           elif self.args.read  and '$5$' in self.input_value :
               re_Hash_id   = str(re.findall('^([$]\w+[$])'   ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'')
               re_hash_salt = str(re.findall('(^[$^]\S+[$])' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'') 
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
               print(B+'[*]'+W+R+' Hash      : '+Y+Hash+W)
               time.sleep(1)
               print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
               time.sleep(2)
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value[0:52],'\n','                   : ', self.input_value[52:] +W)
               count  = 0                            
               second = 0    
               minute = 0    
               hours  = 0   
               count1 = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type )
                   if (count1 == 10): 
                       count1 =0                                                 
                       second+=1                                    
                   if(second == 60):    
                       second = 0    
                       minute+=1    
                   if(minute == 60):    
                       minute = 0    
                       hour+=1;                
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+R+ 'Same Hash Match : '+W,R+crypt_Hash[:52])\
                         ;print('                    : ',crypt_Hash[52:]+W,)  
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W)  
                         print(B+'[*] '+W+P+'Time        '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                         print('         ',B+('='*25)+W)                                                         
                         break
                         exit()
                   print(B+'[*] '+W+B+'Try Password    : '+W,P+secrit+W);print()\
                   ;print(B+'[*] '+W+R+'Try Hash        : ',                  
                   R+hash_type+W+B+crypt_Hash[len(hash_type):52])\
                   ;print('                    : ',crypt_Hash[52:]+W)\
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)\
                   ;print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                   ;print('        ',B+('='*25)+W)      
                   time.sleep(0.1)                          
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
                   count  +=1
                   count1 +=1
               else:  
                   print (B+'\n[*] Password Not Found','\n')
                   print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                   exit() 
                                                                                 
              
           elif self.args.read  and '$2y$' in self.input_value :
               re_Hash_id   = str(re.findall('^([$]\w+[$])'   ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'')
               re_hash_Cost = str(re.findall('[^$]\d+[$^]' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'').replace('$','')               
               hash_type =    str(re.findall('^[$^]\S+[$]......................' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'').rstrip()                         
               Hash = self.input_value.replace(hash_type,'')
               re_hash_print = self.input_value.replace(re_Hash_id,'').replace(re_hash_Cost,'').replace(hash_type,'').replace(Hash,'').replace('$','')
               try:
                  self.path = os.path.abspath(self.args.wordlist)
                  self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                  self.line = self.list.read()            
                  passwords = self.line.split()
               except FileNotFoundError :
                  print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                  exit()             
               print(B+'[*]'+W+R+' Hash Id   :'+W+Y+ ' bcrypt-Version: 2y '+W+B+ ' crypt: '+W+R+'[blowfish hash]'+W)
               time.sleep(1)
               print(B+'[*]'+W+R+' Cost      :'+W+Y,re_hash_Cost)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash Salt : '+Y+re_hash_print+W)
               time.sleep(1)
               print(B+'[*]'+W+R+' Hash      : '+Y+Hash+W)
               time.sleep(1)
               print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
               time.sleep(2)
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value[0:52],'\n','                   : ', self.input_value[52:] +W)
               count  = 0                            
               second = 0    
               minute = 0    
               hours  = 0   
               count1 = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type )
                   if (count1 == 5): 
                       count1 =0                                                 
                       second+=1                                    
                   if(second == 60):    
                       second = 0    
                       minute+=1    
                   if(minute == 60):    
                       minute = 0    
                       hour+=1;                
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+R+ 'Same Hash Match : '+W,R+crypt_Hash[:52])\
                         ;print('                    : ',crypt_Hash[52:]+W,)  
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W) 
                         print(B+'[*] '+W+P+'Time        '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                         print('         ',B+('='*25)+W)                                                          
                         break
                         exit()
                   print(B+'[*] '+W+B+'Try Password    : '+W,P+secrit+W);print()\
                   ;print(B+'[*] '+W+R+'Try Hash        : ',                  
                   R+hash_type+W+B+crypt_Hash[len(hash_type):52])\
                   ;print('                    : ',crypt_Hash[52:]+W)\
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)\
                   ;print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                   ;print('        ',B+('='*25)+W)    
                   time.sleep(0)                              
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
                   count  +=1
                   count1 +=1
               else:  
                   print (B+'\n[*] Password Not Found','\n')
                   print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                   exit() 
                                                                              
               
           elif self.args.read  and '$6$' in self.input_value :
               re_Hash_id   = str(re.findall('^([$]\w+[$])'   ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'')
               re_hash_salt = str(re.findall('^[$^]\S+[$]' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'') 
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
               print(B+'[*]'+W+R+' Hash      :'+W,Y+Hash [0:40],'\n','             :',Hash[40:]+W)
               time.sleep(1)
               print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
               time.sleep(2)
               print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value[0:52],'\n','                   : ', self.input_value[52:] +W)
               count  = 0                            
               second = 0    
               minute = 0    
               hours  = 0   
               count1 = 0
               for secrit in passwords :
                   crypt_Hash = crypt.crypt(secrit,hash_type)
                   if (count1 == 10): 
                       count1 =0                                                 
                       second+=1                                    
                   if(second == 60):    
                       second = 0    
                       minute+=1    
                   if(minute == 60):    
                       minute = 0    
                       hour+=1;                
                   if crypt_Hash == self.input_value :
                         print(B+'[*] '+W+R+ 'Same Hash Match : '+W,R+crypt_Hash[:52])\
                         ;print('                    : ',crypt_Hash[52:]+W,'\n')  
                         print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                         print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W) 
                         print(B+'[*] '+W+P+'Time        '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                         print('         ',B+('='*25)+W)                                                          
                         break
                         exit()
                   print(B+'[*] '+W+B+'Try Password    : '+W,P+secrit+W);print()\
                   ; print(B+'[*] '+W+R+'Try Hash        : ',R+hash_type+W+B+crypt_Hash[len(hash_type):52])\
                   ;print('                    : ',crypt_Hash[52:]+W) \
                   ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)\
                   ;print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                   ;print('        ',B+('='*25)+W)  
                   time.sleep(0.1)                                                                     
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
                   count1 +=1
               else:  
                   print (B+'\n[*] Password Not Found','\n')
                   print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                   exit() 
                                                                                                                              
        def control(self):
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]")      
           parser.add_argument("-w","--wordlist" , metavar='' , action=None ,required=True,help ="wordlist of passwords") 
           parser.add_argument("-c","--color" , metavar='' , action=None ,default=False,help ="set color display off") 
           parser.add_argument("-r","--read" , metavar='' , action=None ,help ="read the hash from file input" ) 
           self.args = parser.parse_args()     
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help()         
              exit()                   
        
if __name__ == '__main__':
     Linux_Hash()
