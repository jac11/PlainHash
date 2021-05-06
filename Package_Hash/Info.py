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
             print ('[*] MD4             ')
             print ('[*] MD5             [*] SHA1  ')    
             print ('[*] SHA_224         [*] SHA3_224')
             print ('[*] SHA_256         [*] SHA3_256')
             print ('[*] SHA_384         [*] SHA3_384   ')
             print ('[*] SHA_512         [*] SHA3_512')  
             print ('[*] BLAKE2b         [*] BLAKE2s'+W+'\n')                      
             print (P+'[+] With non-Crypto Hsah Copy String Hash  Into File') 
             print ('[+] Same Like : 5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9')
             print ('[*] then Use -r Option or --read To give File Path' )
             print ('[+] Example : ./PlainHash.py -r /home/hash.txt -w /home/wordlist')
             print ('[+] or Use -H with Hash String')
             print ('[+] Example : ./PlainHash.py -H 5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9 -w /home/wordlist'+W+'\n') 
             print (Y+'[*] Hash Message Authentication Code "HMAC" :','\n','*'*20,'\n')
             print ('[*] HMAC-MD5             [*] HMAC-SHA1  ')    
             print ('[*] HMAC-SHA_224         [*] HMAC-SHA3_224')
             print ('[*] HMAC-SHA_256         [*] HMAC-SHA3_256')
             print ('[*] HMAC-SHA_384         [*] HMAC-SHA3_384   ')
             print ('[*] HMAC-SHA_512         [*] HMAC-SHA3_512')  
             print ('[*] HMAC-BLAKE2b         [*] HMAC-BLAKE2s'+W+'\n') 
             print (P+'[+] With HMAC Hash Copy String Hash  Into File with the key' ) 
             print ('[+] Same Like : 5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9:hashkey')
             print ('[*] then Use -r Option or --read To give File Path' )
             print ('[+] Example : ./PlainHash.py -r /home/hash.txt -w /home/wordlist'+W)             
             print (Y+'='*35,'\n\n','[*] Salt Hash Support :','\n',('*'*25),'\n')
             print ('[*] MD5-CRYPT        [*] SHA1-CRYPT  ')
             print ('[*] SHA256-CRYPT     [*] SHA512-CRYPT  ')
             print ('[*] BCRYPT-[Y]       [*] BCRYPT-[2Y] '+W+'\n')              
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
             print ('[+] Example : ./PlainHash.py -H 8846F7EAEE8FB117AD06BDD830B7586C -w /home/wordlist'+W+'\n')      
             
                    
             print (Banner)      
             exit()
    print_info()
if __name =='__main__':
    Info()     
    
 
 
    
