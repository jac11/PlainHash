#!/usr/bin/env python3

import hashlib
import time
import argparse
import sys
import os

from Package_Hash.Banner import Banner


W='\033[0m'     
R='\033[31m'    
G='\033[0;32m'  
O='\33[37m'     
B='\033[34m'    
P='\033[35m'   
Y='\033[1;33m' 
  
class Plain_Hash :
   
     def __init__(self):
         
         global W
         global R
         global G
         global O
         global B
         global P
         global Y   
                                                      
         print (Banner) 
           
         self.md5_hash  = int(32)                                     
         self.SHA_1     = int(40)
         self.SHA3_224  = int(56)
         self.SHA_256   = int(64)        
         self.SHA3_384  = int(96)
         self.SHA_3_512 = int(128)
         
         self.control()
         self.input_hash() 
         try:         
            if self.args.info and sys.argv[2]=='info':
               from Package_Hash.Info import Info
               run = print_info()
            else :
               print(P+'[*] More Info Use -i info or --info info'+W )  
               exit()
         except IndexError :
               print(P+'[*] More Info Use -i info or --info info'+W )  
               exit()                       
     def input_hash(self):
            
            if self.args.read:               
                try:
                   self.path= os.path.abspath(self.args.read)
                   self.list= open(self.path)             
                   self.line_read =self.list.readline().rstrip().lower() 
                   self.input_value = self.line_read
                   self.hash_id()
                except FileNotFoundError :
                    print(Y+'[*] Hash File','{}'.format(self.path),W+B+' Not Found'+W) 
                    exit()  
            elif self.args.hash:
                self.input_value = sys.argv[2].lower()
                self.hash_id()

     def hash_id(self)  :
       
        try:             
                if len(self.input_value) == self.md5_hash:
                     if  not self.args.wordlist :
                         print (Y+'[*] WordList Required  Use -w '+W)   
                         exit()
                     else:
                         pass
                     time.sleep(1)
                     print()  
                     print(B+'[*]'+W,R+'Hash-Identifier'+W)
                     print(Y+"*"*20+W,'\n')
                     time.sleep(1)
                     print(B+'[*] '+W+R+'Hash  ID  :'+Y+' MD4   |', ' [*] len  :',str(self.md5_hash)+W)
                     print(B+'[*] '+W+R+'Hash  ID  :'+Y+' MD5   |', ' [*] len  :',str(self.md5_hash)+W)
                     time.sleep(1)
                     print(B+'[*] '+W+R+'Hash  ID  :'+Y+' NTLM  |', ' [*] len  :',str(self.md5_hash)+W)
                     time.sleep(1)
                     print((B+'*'*30+W),'\n',B+'[*]'+W+R+' Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
                     time.sleep(2)
                     print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value+W )
                     if self.args.hash or self.args.read : 
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
                            hash_password0 = hashlib.new('md4',secrit.encode()).hexdigest()
                            hash_password = hashlib.md5(secrit.encode()).hexdigest()
                            hash_password1 = hashlib.new('md4',secrit.encode('utf-16le')).hexdigest()
                            
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
                               print(B+'[*] '+W+R+'Hash ID         :'+W+Y+'  MD4  '+W)
                               print(B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                               print(B+'[*] '+W+Y+'Password Count  : '+W,P+str(count)+W) 
                               print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                               print('      ',B+('='*25)+W)                                                                                   
                               exit()                                                       
                            elif hash_password == self.input_value  : 
                               print(B+'[*] '+W+Y+'Same Hash Match : '+W,B+hash_password+W)
                               print(B+'[*] '+W+R+'Hash ID         :'+W+Y+'  MD5  '+W)
                               print(B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                               print(B+'[*] '+W+Y+'Password Count  : '+W,P+str(count)+W)
                               print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                               print('      ',B+('='*25)+W)                                                                                    
                               exit()
                            elif hash_password1 == self.input_value : 
                               print(B+'[*] '+W+R+'Same Hash Match : ',hash_password1+W)
                               print(B+'[*] '+W+B+'Hash ID         :  Windows NTLM-Hash '+W)
                               print(B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                               print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W) 
                               print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                               print('      ',B+('='*25)+W)                                                              
                               exit()   
                            print(B+'[*] '+W+P+'Try Password    : '+W,P+secrit+W)\
                            ;print(B+'[*] '+W+R+'Try MD4 Hash    : '+W,R+hash_password0+W)\
                            ;print(B+'[*] '+W+Y+'Try MD5 Hash    : ',hash_password+W)\
                            ;print(B+'[*] '+W+B+'Try NTLM-Hash   : ',hash_password1+W)\
                            ;print(B+'[*] '+W+Y+'Password Count  : '+W,P+str(count)+W)\
                            ;print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                            ;print('      ',B+('='*25)+W)                                
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
                            count1+=1
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
                        print(B+'[*] '+W,R+'Hash-Identifier'+W)
                        print(Y+"*"*20+W,'\n')
                        time.sleep(1)
                        print(B+'[*] '+W+R+'Hash  ID  : SHA1   |', ' [*] len  :'+W,R+str(self.SHA_1)+W,'\n')
                        print((B+'*'*30+W),'\n',B+'[*]'+W+R+' Plain_Hash_Start','\n',(B+'-'*20+W),'\n')
                        time.sleep(2)
                        print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value+W )
                        if self.args.hash or self.args.read :
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
                               hash_password = hashlib.sha1(secrit.encode()).hexdigest()
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
                                  print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                  print('      ',B+('='*25)+W)                                                               
                                  exit()
                               print(B+'[*] '+W+R+'Try Password    : '+W,R+secrit+W);print(B+'[*] '+W+R+'Try Hash        : '+W,B+hash_password+W)\
                               ;print(B+'[*] '+W+B+'Password Count  : '+W,R+str(count)+W)\
                               ;print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                               ;print('      ',B+('='*25)+W) 
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
                elif len(self.input_value) == self.SHA3_384 :
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
                                print (B+'[*] '+W+R+'Hash  ID  : SHA_384  |', ' [*] len  :',str(self.SHA3_384)+W)
                                time.sleep(1)
                                print (B+'[*] '+W+Y+'Hash  ID  : SHA3_384 |',' [*] len  :'+W,Y+str(self.SHA3_384)+W,'\n') 
                                print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
                                time.sleep(2)
                                print(B+'[*] '+W+B+'Original Hash      : '+W,O+self.input_value[:48])\
                                ;print('                       : ',self.input_value[48:]+W)  
                                if self.args.hash or self.args.read:                                  
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
                                      hash_password = hashlib.sha384(secrit.encode()).hexdigest()
                                      hash_password1 = hashlib.sha3_384(secrit.encode()).hexdigest()
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
                                             print(B+'[*] '+W+B+'Hash ID            :  SHA_384 '+W) 
                                             print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                             print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W) 
                                             print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                             print('         ',B+('='*25)+W) 
                                             exit()                         
                                      elif hash_password1 ==self.input_value :
                                             print(B+'[*] '+W+Y+'Same Hash Match    : ',hash_password1[48:])\
                                             ;print('                       : ',hash_password1[48:]+W)
                                             print(B+'[*] '+W+B+'Hash ID            :  SHA3_384  '+W) 
                                             print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                             print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                             print(B+'[*] '+W+P+'Time              '+W+R+' | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                             print('         ',B+('='*25)+W)
                                             exit()
                                      print(B+'[*] '+W+B+'Try Password       : '+W,P+secrit); print(B+'[*] '+W+R+'Try Hash sha_384   : ',hash_password[:48])\
                                      ;print('                       : ',hash_password[48:]+W)\
                                      ;print(B+'[*] '+W+Y+'Try Hash sha3_384  : ',hash_password1[48:])\
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
                            print (B+'[*] '+W+R+'Hash  ID  : SHA256   |', ' [*] len  :'+W+R+str(self.SHA_256)+W)
                            time.sleep(1)
                            print (B+'[*] '+W+Y+'Hash  ID  : SHA3_256 |',' [*] len  :'+W+Y+str(self.SHA_256)+W)
                            time.sleep(1)
                            print (B+'[*] '+W+B+'Hash  ID  : BLAKE2S  |' ,' [*] len  :'+W+B+str(self.SHA_256)+W) 
                            print((B+'*'*30+W),'\n',B+'[*] '+W+R+'Plain_Hash_Start','\n',(B+'-'*20+W),'\n')
                            time.sleep(2)
                            print(B+'[*] '+W+B+'Original Hash      : '+W,O+self.input_value[:32],'\n','                      : ', self.input_value[32:] +W+'\n') 
                            if self.args.hash or self.args.read:
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
                                  hash_password  = hashlib.sha256(secrit.encode()).hexdigest()
                                  hash_password1 = hashlib.sha3_256(secrit.encode()).hexdigest()
                                  hash_password2 = hashlib.blake2s(secrit.encode()).hexdigest()
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
                                     print(B+'[*] '+W+B+'Hash ID            :'+W+R+'  sha256 '+W) 
                                     print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                     print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                     print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                     print('         ',B+('='*25)+W)
                                     exit()                           
                                  elif hash_password1 ==self.input_value :
                                       print(B+'[*] '+W+B+'Same Hash Match    : ',hash_password2[0:32])\
                                       ;print('                       : ',hash_password2[32:]+W)  
                                       print(B+'[*] '+W+B+'Hash ID            :'+W+R+'  SHA3_256 '+W) 
                                       print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                       print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)                              
                                       print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                       print('         ',B+('='*25)+W)
                                       exit()   
                                  elif hash_password2 ==self.input_value:
                                       print(B+'[*] '+W+B+'Same Hash Match    : ',hash_password2[0:32])\
                                       ;print('                       : ',hash_password2[32:]+W)  
                                       print(B+'[*] '+W+Y+'Hash ID            :'+W+Y+'  BLAKE2S '+W) 
                                       print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                       print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                       print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                       print('         ',B+('='*25)+W)
                                       exit()                                                                                              
                                  print(B+'[*] '+W+B+'Try Password       : '+W,P+secrit+W);print(); print(B+'[*] '+W+R+'Try Hash sha256    : ',\
                                  hash_password[:32]);print('                       : ',hash_password[32:]+W)\
                                  ;print(B+'[*] '+W+Y+'Try Hash SHA3_256  : ',hash_password1[:32])\
                                  ;print('                       : ',hash_password1[32:]+W)\
                                  ;print(B+'[*] '+W+B+'Try Hash BLAKE2S   : ',hash_password2[:32])\
                                  ;print('                       : ',hash_password2[32:]+W)\
                                  ;print(B+'[*] '+W+R+'Password Count     : ',P+str(count)+W)\
                                  ;print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
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

                                  count  +=1 
                                  count1 +=1          
                               else: 
                                 print (B+'\n[*] Password Not Found','\n')
                                 print ('[*] PLease Try another WordList','\n',('*'*30)+W)
                                 exit() 
                                                      
                elif len(self.input_value)	== self.SHA_3_512 :
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
                              print (B+'[*] '+W+R+'Hash  ID  : SHA3_512    |', ' [*] len  :',str(self.SHA_3_512)+W)
                              time.sleep(1)
                              print (B+'[*] '+W+Y+'Hash  ID  : BLAKE2b     |',' [*] len  :',str(self.SHA_3_512)+W)
                              time.sleep(1)
                              print (B+'[*] '+W+B+'Hash  ID  : SHA512      |' ,' [*] len  :',str(self.SHA_3_512)+W)
                              print((B+'*'*30+W),'\n',B+'[*] '+W+R+'Plain_Hash_Start','\n',(B+'-'*20+W),'\n')
                              time.sleep(2)
                              print(B+'[*] '+W+B+'Original Hash      : '+W,O+self.input_value[:64],'\n','                      : ', self.input_value[64:] +W)
                              print()
                              if self.args.hash or self.args.read:
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
                                     hash_password  = hashlib.sha3_512(secrit.encode()).hexdigest()
                                     hash_password1 = hashlib.blake2b(secrit.encode()).hexdigest()
                                     hash_password2 = hashlib.sha512(secrit.encode()).hexdigest()
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
                                          print(B+'[*] '+W+Y+'Hash ID            :  SHA3_512 '+W) 
                                          print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                          print(B+'[*] '+W+Y+'Password Count     : '+W,P+str(count)+W)
                                          print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                          print('         ',B+('='*25)+W)
                                          exit()                            
                                     elif hash_password1 ==self.input_value :
                                          print(B+'[*]'+W+Y+'Same Hash Match     : ',hash_password1[:64])\
                                          ;print('                       : ',hash_password1[64:]+W) 
                                          print(B+'[*] '+W+B+'Hash ID            :  BLAKE2b '+W) 
                                          print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                          print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                          print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                          print('         ',B+('='*25)+W)
                                          exit()    
                                     elif hash_password2 ==self.input_value:
                                          print(B+'[*] '+W+B+'Same Hash Match    : ',hash_password2[:64])\
                                          ;print('                       : ',hash_password2[64:]+W)
                                          print(B+'[*] '+W+Y+'Hash ID            :  SHA512  '+W) 
                                          print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                          print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                          print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                          print('         ',B+('='*25)+W)
                                          exit()                                            
                                     print(B+'[*] '+W+B+'Try Password       : '+W,P+secrit+W);print(); print(B+'[*] '+W+R+'Try Hash sha3_512  : ',\
                                     hash_password[:64]);print('                       : ',hash_password[64:]+W)\
                                     ;print(B+'[*] '+W+Y+'Try Hash blake2b   : ',hash_password1[:64])\
                                     ;print('                       : ',hash_password1[64:]+W)\
                                     ;print(B+'[*] '+W+B+'Try Hash sha512    : ',hash_password2[:64])\
                                     ;print('                       : ',hash_password2[64:]+W)\
                                     ;print(B+'[*] '+W+R+'Password Count     : ',P+str(count)+W)\
                                     ;print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
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

                                     count  +=1 
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
                                print (B+'[*] '+W+R+'Hash  ID  : SHA3_224  |', ' [*] len  :',str(self.SHA3_224)+W)
                                time.sleep(1)
                                print (B+'[*] '+W+Y+'Hash  ID  : SHA224    |',' [*] len  :'+W,Y+str(self.SHA3_224)+W,'\n') 
                                print((B+'*'*30+W),'\n',B+'[*]'+W+R+'Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
                                time.sleep(2)
                                print(B+'[*] '+W+B+'Original Hash      : '+W,O+self.input_value+W )  
                                if self.args.hash or self.args.read:                                  
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
                                      hash_password = hashlib.sha3_224(secrit.encode()).hexdigest()
                                      hash_password1 = hashlib.sha224(secrit.encode()).hexdigest()
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
                                             print(B+'[*] '+W+B+'Hash ID            :  SHA3_224 '+W) 
                                             print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                             print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)  
                                             print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                             print('            ',B+('='*25)+W)
                                             exit()                         
                                      elif hash_password1 ==self.input_value :
                                             print(B+'[*] '+W+Y+'Same Hash Match    : ',hash_password1+W)  
                                             print(B+'[*] '+W+B+'Hash ID            :  SHA224  '+W) 
                                             print(B+'[*] '+W+R+'Password Found     : '+W,P+secrit+W) 
                                             print(B+'[*] '+W+B+'Password Count     : '+W,P+str(count)+W)
                                             print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)
                                             print('            ',B+('='*25)+W)
                                             exit()
                                      print(B+'[*] '+W+B+'Try Password       : '+W,P+secrit); print(B+'[*] '+W+R+'Try Hash sha3_224  : ',hash_password+W)\
                                      ;print(B+'[*] '+W+Y+'Try Hash sha224    : ',hash_password1+W);print(B+'[*] '+W+R+'Password Count     : '+W,P+str(count)+W)\
                                      ;print(B+'[*] '+W+P+'Time           '+W+R+'    | '+W,O+'%d : %d : %d '%(hours,minute,second)+W)\
                                      ;print('            ',B+('='*25)+W) 
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
                                      count  +=1 
                                      count1 +=1 
                                  else:                        	
                                     print (B+'\n[*] Password Not Found','\n')
                                     print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                                     exit()
                elif "$" in self.input_value :
                     from Package_Hash.Linux_Hash import Linux_Hash
                     run = Linux_Hash()
                     exit()  
                elif "$" not in self.input_value and len( self.input_value)==int(65) :
                     from Package_Hash.Win_NTLM import Win_Hash
                     run = Win_Hash()   
                     exit()
                elif "$" not in self.input_value and ':' in self.input_value:
                     from Package_Hash.HMAC_Hash import HMAC_HASH       
                     run = HMAC_HASH()  
                     exit()                        
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
        parser.add_argument("-H",'--hash' , metavar='' , action=None  ,help ="Hash string ") 
        parser.add_argument("-w","--wordlist" , metavar='' , action=None ,help ="wordlist of passwords") 
        parser.add_argument("-i","--info" , metavar='' , action=None ,help ="Show the Hash Supporting  and Information")        
        parser.add_argument("-r","--read" , metavar='' , action=None ,help ="read the hash from file input") 
        
        self.args = parser.parse_args()        
        if len(sys.argv)!=1 :
            pass
        else:
            parser.print_help()         
            exit()
           
if __name__ == '__main__':
   Plain_Hash()
   
