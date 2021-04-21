#!/usr/bin/env python3

from Package_Hash.Banner import Banner

class Info:
     
    def print_info():
            
             W='\033[0m'     
             R='\033[31m'    
             G='\033[0;32m'  
             O='\33[37m'     
             B='\033[34m'    
             P='\033[35m'   
             Y='\033[1;33m'                          
             print (Y+'[*] Hash Support :','\n','*'*20,'\n')
             print ('[*] MD5             [*] SHA_1 ')
             print ('[*] SHA_256         [*] SHA_3_256')
             print ('[*] SHA3_384        [*] BLAKE2c')
             print ('[*] SHA_3_512       [*] SHA_512')
             print ('[*] BLAKE2b         [*] SHA3_224')
             print ('[*] SHA_224 '+W+'\n')            
             print (P+'[+] With non-Crypto Hsah Copy String Hash  Into File') 
             print ('[+] Same Like : 5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9')
             print ('[*] then Use -r Option or --read To give File Path' )
             print ('[+] Example : ./PlainHash.py - r /home/hash.txt -w /home/wordlist')
             print ('[+] or Use -H with Hash String')
             print ('[+] Example : ./PlainHash.py -H 5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9 -w /home/wordlist'+W+'\n')               
             print (Y+'='*35,'\n\n','[*] Salt Hash Support :','\n',('*'*25),'\n')
             print ('[*] MD5-CRYPT       [*] BCRYPT-[Y]')
             print ('[*] SHA1-CRYPT      [*] SHA256-CRYPT')
             print ('[*] SHA512-CRYPT'+W+'\n')              
             print (P+'[+] With "Crypt Hash" Copy Hash Into File') 
             print ('[+] Example : $6$efxS7PCQU0SZi33L$H7sWCUQJ0dDBKwSZmxwADtp6D553OyjFRUfA3PKnf4JAT625jiRvDBFUTB2501CLCDzNlbjkCqM4PFJsxV9Qx/')
             print ('[*] then Use -r Option or --read To give File Path' )
             print ('[+] Example : ./PlainHash.py - r /home/hash.txt -w /home/wordlist'+W+'\n')             
             print (Y+'='*35,'\n\n','[*] Windows-Hash :','\n',('*'*25),'\n')             
             print ('[*] Windows-NTLM-V1 MD4 Encode[UTF-16LE]'+W+'\n')                                     
             print (P+'[+] With Windows NTLM  Copy  NTLM Hash  Into File') 
             print ('[+] Example: aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C')
             print ('[+] or 8846F7EAEE8FB117AD06BDD830B7586C')
             print ('[+] Example : ./PlainHash.py - r /home/hash.txt -w /home/wordlist')
             print ('[+] or Use -H with NTLM MD4 Hash')
             print ('[+] Example : ./PlainHash.py -H 8846F7EAEE8FB117AD06BDD830B7586C -w /home/wordlist'+W)              
             print (Banner)      
             exit()
    print_info()
if __name =='__main__':
    Info()     
    
 
 
