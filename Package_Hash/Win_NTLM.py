#!/usr/bin/env python3

import re
import os
import sys
import timeit,time
import hashlib
import argparse
from Crypto.Hash import MD4
from Package_Hash.Banner import Banner


W='\033[0m'     
R='\033[31m'    
G='\033[0;32m'  
O='\33[37m'     
B='\033[34m'    
P='\033[35m'   
Y='\033[1;33m' 

 
class Win_Hash:
      def __init__(self):
          self.control()
          if self.args.color :
              W=''     
              R=''    
              G=''  
              O=''     
              B=''    
              P=''   
              Y=''
          self.Hash_id()
          self.Hash_NTLM()
          
      def Hash_id(self):
            
            if self.args.read :               
                try:
                   self.path= os.path.abspath(self.args.read)
                   self.list= open(self.path)             
                   self.line_read =self.list.readline().rstrip().lower() 
                   self.input_value = self.line_read.strip()
                except FileNotFoundError :
                    print(Y+'[*] Hash File','{}'.format(self.path),W+B+' Not Found'+W) 
                    exit()  
            elif self.args.hash:
                self.input_value = sys.argv[2].lower()
                self.Hash_id()

      def Hash_NTLM(self)  :
       
               try:             
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
                     print(B+'[*] '+W+R+'Hash  ID    : MD4   ')
                     print(B+'[*] '+W+R+'Hash  Type  : '+W+Y+'Windows-NTLM-V1 '+W)
                     print(B+'[*] '+W+R+'Encodeing   :',W+Y+'Encode[UTF-16LE]' +W,'\n')
                     time.sleep(2)
                     print((B+'*'*30+W),'\n',B+'[*]'+W+R+' Plain_Hash_Start'+W,'\n',(B+'-'*20+W),'\n')
                     time.sleep(2)
                     print(B+'[*] '+W+Y+'Original Hash   : '+W,O+self.input_value[:33]+W )\
                     ;print(O+'                    : '+W,O+self.input_value[33:]+W)
                     if self.args.read :  
                        try:   
                            self.path = os.path.abspath(self.args.wordlist)
                            self.list = open(self.path,'r',encoding = "ISO-8859-1")             
                            self.line = self.list.read()            
                            passwords = self.line.split()
                        except FileNotFoundError :
                            print(Y+'[*] Wordlist File ','{}'.format(self.path),W+B+' Not Found'+W) 
                            exit()        
                        count  = 0
                        start = timeit.default_timer()
                        for secrit in passwords :                            
                            Hash_LM = str(re.findall('\\w+:',self.input_value)).replace('[','').replace(']','').replace("'",'')
                            Hash_NTLM = str(re.findall(':\\w+',self.input_value)).replace(':','').replace('[','').replace(']','').replace("'",'')
                            hash_password = MD4.new(secrit.encode('utf-16le')).hexdigest()    #hashlib.new('md4',secrit.encode('utf-16le')).hexdigest() 
                            stop = timeit.default_timer()
                            sec = stop  - start
                            fix_time = time.gmtime(sec)
                            result = time.strftime("%H:%M:%S",fix_time) 
                            if hash_password == Hash_NTLM : 
                               print(B+'[*] '+W+R+'Same Hash Match : ',R+Hash_LM+W)\
                               ;print(R+'                    : ',hash_password+W)
                               print (B+'[*] '+W+R+'Password Found  : '+W,P+secrit+W)
                               print(B+'[*] '+W+Y+'Password Count  : '+W,R+str(count)+W) 
                               print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+result+W)
                               print('      ',B+('='*25)+W)                                                          
                               exit()
                            print(B+'[*]'+W+R+' Try Hash        : '+W,Y+Hash_LM+W)\
                            ;print(R+'                    : ',R+hash_password+W)\
                            ;print(B+'[*] '+W+B+'Password Count  : '+W,P+str(count)+W)\
                            ;print(B+'[*] '+W+P+'Time           '+W+R+' | '+W,O+result+W)\
                            ;print('      ',B+('='*25)+W)                           
                            time.sleep(0.0001)                           
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
                        else:  
                            print (B+'\n[*] Password Not Found','\n')
                            print ('[*] PLease Try another WordList','\n',('*'*30)+W) 
                            exit()
               except KeyboardInterrupt:
                      print(Banner)
                      exit()                                                
      def control(self): 
          
           parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]") 
           parser.add_argument("-w","--wordlist" , metavar='' , action=None ,required=True,help ="wordlist of passwords") 
           parser.add_argument("-r","--read" , metavar='' , action=None ,help ="read the hash from file input \
           Example: ./PlainHash.py -r hash.txt -w wordlist")
           parser.add_argument("-c","--color" , action='store_true' ,default=False,help ="set color display off")  
           self.args = parser.parse_args()     
           if len(sys.argv)!=1 :
              pass
           else:
              parser.print_help()         
              exit()                   
        
if __name__ == '__main__':
     Win_Hash()
    
