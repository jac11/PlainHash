#!/usr/bin/env python3

import os
import re
import sys
import time
import hmac
import hashlib
import argparse
from Package_Hash.Banner import Banner


W='\033[0m'     
R='\033[31m'    
G='\033[0;32m'  
O='\33[37m'     
B='\033[34m'    
P='\033[35m'   
Y='\033[1;33m' 

class HMAC_HASH :
   
     def __init__(self):
         
         global W
         global R
         global G
         global O
         global B
         global P
         global Y   
                                                     
         self.md5_hash  = int(32)                                     
         self.SHA_1     = int(40)
         self.SHA3_224  = int(56)
         self.SHA_256   = int(64)        
         self.SHA3_384  = int(96)
         self.SHA_3_512 = int(128)

         self.control()
         self.input_hash()                        
     def input_hash(self):
            
            if self.args.read:               
                try:
                   self.path= os.path.abspath(self.args.read)
                   self.list= open(self.path)             
                   self.line_read =self.list.readline().rstrip().lower() 
                   self.input_value = self.line_read
                   self.hash_type = str(re.findall('\S+[:^]',  self.input_value)).replace("[",'').replace("]",'').replace("'",'').rstrip()
                   self.re_Hash_Key  = str(re.findall('[:^]\S+',  self.input_value)).replace("[",'').replace("]",'').replace("'",'').replace(':','')
                   self.re_HasH = str(re.findall('\S+[:^]' ,  self.input_value)).replace("[",'').replace("]",'').replace("'",'').replace(':','') 
                   self.input_value = self.input_value.replace(':','').replace(self.re_Hash_Key,'')
                   self.HMAC_hash()
                   
                except FileNotFoundError :
                    print(Y+'[*] Hash File','{}'.format(self.path),W+B+' Not Found'+W) 
                    exit()  
     def HMAC_hash(self)  :
       
        try:             
                if len(self.input_value) == self.md5_hash :
                     if  not self.args.wordlist :
                         print (Y+'[*] WordList Required  Use -w '+W)   
                         exit()
                     else:
                         pass
                     time.sleep(1)
                     print()  
                     print(B+'[*] '+W,R+'Hash-Identifier'+W)
                     print(Y+"*"*20+W,'\n')
                     time.sleep(1)
                     print(B+'[*] '+W+R+'Hash  ID  :'+Y+' HMAC-MD5  '+W)
                     time.sleep(1)
                     print(B+'[*] '+W+R+'Hash  KEY : '+Y+self.re_Hash_Key +W)  
                     time.sleep(1) 
                     print(B+'[*] '+W+R+'Hash      : '+Y+self.re_HasH+W)                 
                     time.sleep(1)
                     print((B+'*'*30+W),'\n',B+'[*]'+W+R+' Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
                     time.sleep(2)
                     print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value+W )
                     if  self.args.read : 
                        try:    
                           self.path = os.path.abspath(self.args.wordlist)
                           self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                           self.line = self.list.read()            
                           passwords = self.line.split()
                        except FileNotFoundError :
                            print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                            exit()  
                        count  = 0
                        second = 0    
                        minute = 0    
                        hours  = 0   
                        count1 = 0 
                        for secrit in passwords :
                            hash_password0 = hmac.new(self.re_Hash_Key.encode(),secrit.encode(),hashlib.md5).hexdigest()
                            if (count1 == 10): 
                               count1 =0                                                 
                               second+=1  
                               count_time =0  
                            if(second == 60):    
                               second = 0    
                               minute+=1    
                            if(minute == 60):    
                               minute = 0    
                               hour+=1; 
                            if hash_password0 == self.input_value  : 
                               print(B+'[*] '+W+Y+'Same Hash Match : '+W,B+hash_password0+W)
                               print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                               print(B+'[*] '+W+Y+'Password Count  : '+W,P+str(count)+W)  
                               print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                               print('         ',B+('='*25)+W)                                                         
                               exit()                                                       

                            print(B+'[*] '+W+P+'Try Password    : '+W,P+secrit+W)\
                            ;print(B+'[*] '+W+R+'Try HMAC-MD5    : '+W,R+hash_password0+W)\
                            ;print(B+'[*] '+W+Y+'Password Count  : '+W,P+str(count)+W)\
                            ;print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                            ;print('           ',B+('='*25)+W)
                            run_time = Time_count()
                            time.sleep(0.1)                           
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
                elif len(self.input_value) == self.SHA_1 :
                        if  not self.args.wordlist :
                            print (Y+'[*] WordList Required  Use -w '+W)   
                            exit()
                        else:
                             pass      
                        time.sleep(1)  
                        print()  
                        print(B+'[*] '+W,R+' Hash-Identifier'+W)
                        print(Y+"*"*20+W,'\n')
                        time.sleep(1)
                        print(B+'[*] '+W+R+'Hash  ID  :'+W+Y+' HMAC-SHA1 '+W)
                        time.sleep(1)
                        print(B+'[*] '+W+R+'Hash  Key :'+W,Y+self.re_Hash_Key+W)
                        time.sleep(1)
                        print((B+'*'*30+W),'\n',B+'[*]'+W+R+' Plain_Hash_Start','\n',(B+'-'*20+W),'\n')
                        time.sleep(2)
                        print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value+W )
                        if  self.args.read :
                           try:    
                              self.path = os.path.abspath(self.args.wordlist)
                              self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                              self.line = self.list.read()            
                              passwords = self.line.split()
                           except FileNotFoundError :
                             print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                             exit()  
                           count  = 0
                           second = 0    
                           minute = 0    
                           hours  = 0   
                           count1 = 0 
                           for secrit in passwords :
                               hash_password = hmac.new(self.re_Hash_Key.encode(),secrit.encode(),hashlib.sha1).hexdigest()
                               if (count1 == 10): 
                                   count1 =0                                                 
                                   second+=1   
                               if(second == 60):    
                                   second = 0    
                                   minute+=1    
                               if(minute == 60):    
                                   minute = 0    
                                   hour+=1; 
                               if hash_password == self.input_value : 
                                  print(B+'[*] '+W+Y+'Same Hash Match : '+W,B+hash_password+W)
                                  print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                                  print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W)
                                  print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                  print('         ',B+('='*25)+W)                                                                
                                  exit()
                               print(B+'[*] '+W+R+'Try Password    : '+W,R+secrit+W);print(B+'[*] '+W+R+'Try Hash        : '+W,B+hash_password+W)\
                               ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)\
                               ;print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                               ;print('           ',B+('='*25)+W)
                               time.sleep(0.1)                           
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
                elif len(self.input_value) == self.SHA3_384  :
                                if  not self.args.wordlist :
                                    print (Y+'[*] WordList Required  Use -w '+W)   
                                    exit()
                                else:
                                    pass           	
                                time.sleep(1)  
                                print()  
                                print(B+'[*] '+W,R+'Hash-Identifier'+W)
                                print(Y+"*"*20+W,'\n')
                                time.sleep(1)
                                print (B+'[*] '+W+R+'Hash  ID  : HMAC-SHA_384 '+W)
                                time.sleep(1)
                                print (B+'[*] '+W+Y+'Hash  ID  : HMAC-SHA3_384 '+W) 
                                time.sleep(1)
                                print (B+'[*] '+W+B+'Hash  Key :'+W,P+self.re_Hash_Key+W) 
                                time.sleep(1)
                                print((B+'*'*30+W),'\n',B+'[*] '+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
                                time.sleep(2)
                                print(B+'[*] '+W+B+'Original Hash      : '+W,O+self.input_value[:48])\
                                ;print('                       : ',self.input_value[48:]+W)  
                                if  self.args.read:                                  
                                  try:    
                                     self.path = os.path.abspath(self.args.wordlist)
                                     self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                                     self.line = self.list.read()            
                                     passwords = self.line.split()
                                  except FileNotFoundError :
                                      print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                                      exit()  
                                  count  = 0
                                  second = 0    
                                  minute = 0    
                                  hours  = 0   
                                  count1 = 0  
                                  for secrit in passwords :
                                      hash_password =  hmac.new(self.re_Hash_Key.encode(),secrit.encode(),hashlib.sha384).hexdigest()
                                      hash_password1 = hmac.new(self.re_Hash_Key.encode(),secrit.encode(),hashlib.sha3_384).hexdigest()
                                      if (count1 == 10): 
                                          count1 =0                                                 
                                          second+=1   
                                      if(second == 60):    
                                          second = 0    
                                          minute+=1    
                                      if(minute == 60):    
                                          minute = 0    
                                          hour+=1; 
                                      if hash_password == self.input_value :
                                             print(B+'[*] '+W+R+'Same Hash Match    : ',hash_password[:48])\
                                             ;print('                       : ',hash_password[48:]+W)                                              
                                             print (B+'[*] '+W+B+'Hash ID            :  HMAC-SHA_384 '+W) 
                                             print (B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                             print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W) 
                                             print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                             print('         ',B+('='*25)+W) 
                                             exit()                         
                                      elif hash_password1 ==self.input_value :
                                             print(B+'[*] '+W+Y+'Same Hash Match    : ',hash_password1[48:])\
                                             ;print('                       : ',hash_password1[48:]+W)
                                             print (B+'[*] '+W+B+'Hash ID            :  HMAC-SHA3_384  '+W) 
                                             print (B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                             print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                             print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                             print('         ',B+('='*25)+W)
    
                                             exit()
                                      print(B+'[*] '+W+B+'Try Password       : '+W,P+secrit); print(B+'[*] '+W+R+'Try HMAC-SHA_384   : ',hash_password[:48])\
                                      ;print('                       : ',hash_password[48:]+W)\
                                      ;print(B+'[*] '+W+Y+'Try HMAC-SHA3_384  : ',hash_password1[48:])\
                                      ;print('                       : ',hash_password1[48:]+W)\
                                      ;print(B+'[*] '+W+R+'Password Count     : '+W,P+str(count)+W)\
                                      ;print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                                      ;print('           ',B+('='*25)+W)
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
                                                                
                elif len(self.input_value)== self.SHA_256 :
                            if  not self.args.wordlist :
                                print (Y+'[*] WordList Required  Use -w '+W)   
                                exit()
                            else:
                                pass      
                            time.sleep(1)  
                            print()  
                            print(B+'[*] '+W,R+'Hash-Identifier'+W)
                            print(Y+"*"*20+W,'\n')
                            time.sleep(1)
                            
                            print (B+'[*] '+W+R+'Hash  ID  : HMAC-SHA256   ')
                            time.sleep(1)
                            print (B+'[*] '+W+Y+'Hash  ID  : HMAC-SHA3_256 ')
                            time.sleep(1)
                            print (B+'[*] '+W+B+'Hash  ID  : HMAC-BLAKE2S ')
                            time.sleep(1)
                            print (B+'[*] '+W+B+'Hash  Key :'+W,P+self.re_Hash_Key+W)
                            time.sleep(1)
                            print((B+'*'*30+W),'\n',B+'[*] '+W+R+'Plain_Hash_Start','\n',(B+'-'*20+W),'\n')
                            time.sleep(2)
                            print(B+'[*] '+W+B+'Original Hash      : '+W,O+self.input_value[:32],'\n','                      : ', self.input_value[32:] +W+'\n') 
                            if  self.args.read:
                               try:    
                                  self.path = os.path.abspath(self.args.wordlist)
                                  self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                                  self.line = self.list.read()            
                                  passwords = self.line.split()
                               except FileNotFoundError :
                                  print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                                  exit()  
                               count  = 0
                               second = 0    
                               minute = 0    
                               hours  = 0   
                               count1 = 0   
                               for secrit in passwords :
                                  hash_password  = hmac.new(self.re_Hash_Key.encode(),secrit.encode(),hashlib.sha256).hexdigest()                                  
                                  hash_password1 = hmac.new(self.re_Hash_Key.encode(),secrit.encode(), hashlib.sha3_256).hexdigest()
                                  hash_password2 = hmac.new(self.re_Hash_Key.encode(),secrit.encode(), hashlib.blake2s).hexdigest()
                                  if (count1 == 10): 
                                      count1 =0                                                 
                                      second+=1   
                                  if(second == 60):    
                                      second = 0    
                                      minute+=1    
                                  if(minute == 60):    
                                       minute = 0    
                                       hour+=1;
                                  if hash_password == self.input_value :
                                     print(B+'[*] '+W+B+'Same Hash Match    : ',hash_password2[:32])\
                                     ;print('                       : ',hash_password2[32:]+W)  
                                     print(B+'[*] '+W+B+'Hash ID            :'+W+R+'  HMAC-SHA256 '+W) 
                                     print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                     print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W) 
                                     print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                     print('         ',B+('='*25)+W)
                                     exit()                           
                                  elif hash_password1 ==self.input_value :
                                       print(B+'[*] '+W+B+'Same Hash Match    : ',hash_password2[0:32])\
                                       ;print('                       : ',hash_password2[32:]+W)  
                                       print(B+'[*] '+W+B+'Hash ID            :'+W+R+'  HMAC-SHA3_256 '+W) 
                                       print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                       print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W) 
                                       print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                       print('         ',B+('='*25)+W)                              
                                       exit()   
                                  elif hash_password2 ==self.input_value:
                                       print(B+'[*] '+W+B+'Same Hash Match    : ',hash_password2[0:32])\
                                       ;print('                       : ',hash_password2[32:]+W)  
                                       print(B+'[*] '+W+Y+'Hash ID            :'+W+Y+' HMAC-BLAKE2S'+W) 
                                       print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                       print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                       print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                       print('         ',B+('='*25)+W)
                                       exit()                                                                                              
                                  print(B+'[*] '+W+B+'Try Password       : '+W,P+secrit+W);print(); print(B+'[*] '+W+R+'Try HMAC-SHA256    : ',\
                                  hash_password[:32]);print('                       : ',hash_password[32:]+W)\
                                  ;print(B+'[*] '+W+Y+'Try HMAC-SHA3_256  : ',hash_password1[:32])\
                                  ;print('                       : ',hash_password1[32:]+W)\
                                  ;print(B+'[*] '+W+B+'Try HMAC-BLAKE2S   : ',hash_password2[:32])\
                                  ;print('                       : ',hash_password2[32:]+W+'\n')\
                                  ;print(B+'[*] '+W+R+'Password Count     : ',P+str(count)+W)\
                                  ;print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                                  ;print('           ',B+('='*25)+W)
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
                                                      
                elif len(self.input_value)== self.SHA_3_512 :
                              if  not self.args.wordlist :
                                  print (Y+'[*] WordList Required  Use -w '+W)   
                                  exit()
                              else:
                                  pass      
                              time.sleep(1)  
                              print()  
                              print(B+'[*]'+W,R+' Hash-Identifier'+W)
                              print(Y+"*"*20+W,'\n')
                              time.sleep(1)
                              print (B+'[*] '+W+R+'Hash  ID  : HMAC-SHA3_512  '+W)
                              time.sleep(1)
                              print (B+'[*] '+W+Y+'Hash  ID  : HMAC-BLAKE2b   '+W)
                              time.sleep(1)
                              print (B+'[*] '+W+B+'Hash  ID  : HMAC-SHA512    '+W)
                              time.sleep(1)
                              print (B+'[*] '+W+B+'Hash  Key :'+W,P+self.re_Hash_Key+W)
                              print((B+'*'*30+W),'\n',B+'[*] '+W+R+'Plain_Hash_Start','\n',(B+'-'*20+W),'\n')
                              time.sleep(2)
                              print(B+'[*] '+W+B+'Original Hash      : '+W,O+self.input_value[:64],'\n','                      : ', self.input_value[64:] +W)
                              print()
                              if  self.args.read:
                                 try:    
                                    self.path = os.path.abspath(self.args.wordlist)
                                    self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                                    self.line = self.list.read()            
                                    passwords = self.line.split()
                                 except FileNotFoundError :
                                    print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                                    exit()                        
                                 count  = 0
                                 second = 0    
                                 minute = 0    
                                 hours  = 0   
                                 count1 = 0   
                                 for secrit in passwords :
                                     hash_password  = hmac.new(self.re_Hash_Key.encode(),secrit.encode(),hashlib.sha3_512).hexdigest() 
                                     hash_password1 = hmac.new(self.re_Hash_Key.encode(),secrit.encode(),hashlib.blake2b).hexdigest()
                                     hash_password2 = hmac.new(self.re_Hash_Key.encode(),secrit.encode(),hashlib.sha512).hexdigest()
                                     if (count1 == 10): 
                                          count1 =0                                                 
                                          second+=1   
                                     if(second == 60):    
                                          second = 0    
                                          minute+=1    
                                     if(minute == 60):    
                                          minute = 0    
                                          hour+=1;
                                     if hash_password == self.input_value :
                                          print(B+'[*] '+W+R+'Same Hash Match    : '+W,R+hash_password[:64])\
                                          ;print('                       : ',hash_password[64:]+W)  
                                          print (B+'[*] '+W+Y+'Hash ID            :  HMAC-SHA3_512 '+W) 
                                          print (B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                          print(B+'[*] '+W+Y+'Password Count     : '+W,P+str(count)+W)
                                          print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                          print('         ',B+('='*25)+W)
                                          exit()                            
                                     elif hash_password1 ==self.input_value :
                                          print(B+'[*]'+W+Y+'Same Hash Match     : ',hash_password1[:64])\
                                          ;print('                       : ',hash_password1[64:]+W) 
                                          print (B+'[*] '+W+B+'Hash ID            :  HMAC-BLAKE2b '+W) 
                                          print (B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                          print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                          print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                          print('         ',B+('='*25)+W)
                                          exit()    
                                     elif hash_password2 ==self.input_value:
                                          print(B+'[*] '+W+B+'Same Hash Match    : ',hash_password2[:64])\
                                          ;print('                       : ',hash_password2[64:]+W)
                                          print (B+'[*] '+W+Y+'Hash ID            :  HMAC-SHA512  '+W) 
                                          print (B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                          print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                          print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                          print('         ',B+('='*25)+W)
                                          exit()                                            
                                     print(B+'[*] '+W+B+'Try Password       : '+W,P+secrit+W);print(); print(B+'[*] '+W+R+'Try HMAC-SHA3_512  : ',\
                                     hash_password[:64]);print('                       : ',hash_password[64:]+W)\
                                     ;print(B+'[*] '+W+Y+'Try HMAC-blake2b   : ',hash_password1[:64])\
                                     ;print('                       : ',hash_password1[64:]+W)\
                                     ;print(B+'[*] '+W+B+'Try HMAC-SHA_512   : ',hash_password2[:64])\
                                     ;print('                       : ',hash_password2[64:]+W)\
                                     ;print(B+'[*] '+W+R+'Password Count     : ',P+str(count)+W)\
                                     ;print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                                     ;print('           ',B+('='*25)+W)
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
                elif len(self.input_value)== self.SHA3_224 : 
                                if  not self.args.wordlist :
                                    print (Y+'[*] WordList Required  Use -w '+W)   
                                    exit()
                                else:
                                    pass           	
                                time.sleep(1)  
                                print()  
                                print(B+'[*] '+W,R+'Hash-Identifier'+W)
                                print(Y+"*"*20+W,'\n')
                                time.sleep(1)
                                print (B+'[*] '+W+R+'Hash  ID  : HMAC-SHA3_224 '+W)
                                time.sleep(1)
                                print (B+'[*] '+W+Y+'Hash  ID  : HMAC-SHA_224  '+W)
                                time.sleep(1)
                                print (B+'[*] '+W+Y+'Hash  Key : '+W,P+self.re_Hash_Key+W)  
                                time.sleep(1) 
                                print((B+'*'*30+W),'\n',B+'[*] '+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
                                time.sleep(2)
                                print(B+'[*] '+W+B+'Original Hash      : '+W,O+self.input_value+W )  
                                if  self.args.read:                                  
                                  try:    
                                     self.path = os.path.abspath(self.args.wordlist)
                                     self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                                     self.line = self.list.read()            
                                     passwords = self.line.split()
                                  except FileNotFoundError :
                                      print(Y+'[*] Wordlist File','{}'.format(self.path),W+B+' Not Found'+W) 
                                      exit()  
                                  count  = 0
                                  second = 0    
                                  minute = 0    
                                  hours  = 0   
                                  count1 = 0   
                                  for secrit in passwords :
                                      hash_password  =  hmac.new(self.re_Hash_Key.encode(),secrit.encode(), hashlib.sha3_224).hexdigest()
                                      hash_password1 = hmac.new(self.re_Hash_Key.encode(),secrit.encode(), hashlib.sha224).hexdigest()
                                      if (count1 == 10): 
                                          count1 =0                                                 
                                          second+=1   
                                      if(second == 60):    
                                          second = 0    
                                          minute+=1    
                                      if(minute == 60):    
                                          minute = 0    
                                          hour+=1;
                                      if hash_password == self.input_value :
                                             print(B+'[*] '+W+R+'Same Hash Match    : ',hash_password+W)  
                                             print(B+'[*] '+W+B+'Hash ID            :  HMAC-SHA3_224 '+W) 
                                             print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                             print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                             print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                             print('         ',B+('='*25)+W) 
                                             exit()                         
                                      elif hash_password1 ==self.input_value :
                                             print(B+'[*] '+W+Y+'Same Hash Match    : ',hash_password1+W)  
                                             print(B+'[*] '+W+B+'Hash ID            :  HMAC-SHA224  '+W) 
                                             print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                             print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                             print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                             print('         ',B+('='*25)+W)    
                                             exit()
                                      print(B+'[*] '+W+B+'Try Password       : '+W,P+secrit); print(B+'[*] '+W+R+'Try HMAC-SHA3_224  : ',hash_password+W)\
                                      ;print(B+'[*] '+W+Y+'Try HMAC-SHA_224   : ',hash_password1+W);print(B+'[*] '+W+R+'Password Count     : '+W,P+str(count)+W)\
                                      ;print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                                      ;print('           ',B+('='*25)+W)
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
                                      count +=1 
                                      count1 +=1
                                  else:                        	
                                     print (B+'\n[*] Password Not Found','\n')
                                     print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                                  
                else :
                   print(Y+'\n[*] Hash-Identifier\n',("*"*20),'\n') 
                   print(P+'[*] Input Hash Not In Our Database '+W)
                   print(P+'[*] With "Crypt Hash" Use -r Option or --read'+W)   
                   print(P+'[*] With "Windows-NTLM" Use -r Option or --read'+W)                

        except KeyboardInterrupt:
              print(Banner)
              exit()   
              
     def control(self):
    
        parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]")       
        parser.add_argument("-w","--wordlist" , metavar='' , action=None ,help ="wordlist of passwords")       
        parser.add_argument("-r","--read" , metavar='' , action=None ,help ="read the hash from file input") 
        
        self.args = parser.parse_args()        
        if len(sys.argv)!=1 :
            pass
        else:
            parser.print_help()         
            exit()
           
if __name__ == '__main__':
   HMAC_HASH()
