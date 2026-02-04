#!/usr/bin/env python 
import paramiko
import os
from datetime import datetime
import timeit,time
import argparse
import sys
import base64
import random

W='\033[0m'     
R='\033[31m'    
G='\033[0;32m'  
O='\33[37m'     
B='\033[34m'    
P='\033[35m'   
Y='\033[1;33m' 

class SSHCRACK:
        def __init__(self):
            self.start = timeit.default_timer()
            self.control()
            self.crack_ssh_key(key_path=self.args.sshkey,wordlist=self.args.wordlist)
        def generate_fake_key(self):
            lines1 = []
            lines1.append(self.lines[0])
            stop = timeit.default_timer()
            sec = stop  - self.start
            fix_time = time.gmtime(sec)
            self.timetotal = time.strftime("%H:%M:%S",fix_time)   

            for _ in range(4):
                fake_data = ''.join(random.choices(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
                    k=70
                ))
                lines1.append(fake_data)
            
            for i, line in enumerate(lines1[:5]):

                if line.strip():
                    print(f"{Y}      {line.strip()[:80]}{'...' if len(line) > 80 else ''}{W}")
            print(B+'\n[*] '+R+'Time                       '+W+R+' : '+W,O+self.timetotal+W)
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
      
        def analyze_key(self,key_path):
            print()  
            print(B+'[*]'+W,R+'SSH-KEY -Identifier'+W)
            print(Y+"*"*20+W,'\n')
            if os.path.exists(key_path):
                file_stats = os.stat(key_path)
                file_size = file_stats.st_size
                created_time = datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                modified_time = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                print(f"{B}[*]{R} Key file            : {O} {key_path}")
                time.sleep(.20)
                print(f"{B}[*]{R} File size           : {O} {file_size}{R} bytes{W}")
                time.sleep(.20)
                print(f"{B}[*]{R} Created             : {O} {created_time}{W}")
                time.sleep(.20)
                print(f"{B}[*]{R} Last modified       : {O} {modified_time}{W}")
                time.sleep(.20)
            else:
                print(f"{B}[*]{R} Error: Key file     : {O}{key_path}{R}  not found!{W}")
                return None
            key_type = None
            key_size = None
            is_encrypted = False
            
            try:
                key = paramiko.RSAKey.from_private_key_file(key_path, password=None)
                key_type = "RSA"
                key_size = key.get_bits()
                is_encrypted = False
            except paramiko.ssh_exception.PasswordRequiredException:
                is_encrypted = True
                print(B+'[*]'+W,R+'requires password   : '+P,"True"+W)
                time.sleep(.20)
                try:
                    paramiko.RSAKey.from_private_key_file(key_path, password="dummy")
                except Exception as e:
                    if "RSA" in str(e):
                        key_type = "RSA"
                    elif "DSA" in str(e):
                        key_type = "DSA"
                    elif "ECDSA" in str(e):
                        key_type = "ECDSA"
            except Exception as e:
                print(f"{B}[*]{R} Error analyzing key       : {O}{e}{W}")
                time.sleep(.20)
            if key_type:
                print(f"[*] Key type: {key_type}")
                time.sleep(.20)
                print(f"{B}[*]{R}[*] Key type            : {O} {key_type}{W}")
                time.sleep(.20)
                if key_size:
                    print(f"{B}[*]{R} File size           : {O} {file_size}{R} bits{W}")
                    time.sleep(.20)
                else:
                    print(f"{B}[*]{R} Key size: Unknown        : {O}(encrypted)!{W}")
                    time.sleep(.20)
            else:
                print(f"{B}[*]{R} Key type            : {O} (Unknown)!{W}")
                time.sleep(.20)

            print(f"{B}[*]{R} Encrypted           : {O} {is_encrypted}{W}")
            time.sleep(.20)
            
            try:
                with open(key_path, 'r') as f:
                    self.lines = f.readlines()
                    if self.lines: 
                        print(B+'[*]'+W,R+'Key file format'+W)
                        print(Y+"*"*20+W,'\n')

                        for i, self.line in enumerate(self.lines[:5]):
                            if self.line.strip():
                                print(f"{P}  Line {i+1}: {self.line.strip()[:80]}{'...' if len(self.line) > 80 else ''}{W}")
            except:
                try:
                    with open(key_path, 'rb') as f:
                        header = f.read(100)
                        print(f"\n{B}[*]{R} Info                  : Key appears to be in binary/OpenSSH format")
                        print(f"{B}[*]{R} First 100 bytes (hex)   : {header.hex()[:80]}...")
                except:
                    pass
            
            print(Y+"*"*60+W,'\n')

            return {
                'path': key_path,
                'size_bytes': file_size,
                'type': key_type,
                'bits': key_size,
                'encrypted': is_encrypted
            }

        def crack_ssh_key(self,key_path, wordlist):
            
            self.timetotal = ""
            key_info = self.analyze_key(key_path)
            if not key_info:
                return None
            
            if not key_info['encrypted']:
                print(f"{B}[*]{R} Key NOT encrypted           : {O} no cracking needed!{W}")
                try:
                    key = paramiko.RSAKey.from_private_key_file(key_path, password=None)
                    print(f"[*] Successfully loaded unencrypted key")
                    print(f"[*] Key size: {key.get_bits()} bits")
                    print(f"[*] Public key (Base64): {key.get_base64()}")
                    return key
                except Exception as e:
                    print(f"[!] Error loading key: {e}")
                return None
            print(f"{B}[*]{R} Status                      : Starting brute-force attack...")
            print(f"{B}[*]{R} Wordlist                    : {O}{wordlist}{W}")
            
            total_passwords = 0
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as wl:
                total_passwords = sum(1 for line in wl if line.strip())
            
            print(f"{B}[*]{R} Total passwords to try      :{O} {total_passwords:,}{W}\n\n{O}{'*'*20}\n")
            
            found = False
            start_time = datetime.now()
            
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as wl:
                for i, line in enumerate(wl, 1):
                    password = line.strip()

                    if not password:
                        continue
                    
                    try:
                        key = paramiko.RSAKey.from_private_key_file(key_path, password=password)

                        found = True
                        elapsed = (datetime.now() - start_time).seconds
                        
                        print(f"\n{B}[+]{P} CRACKING SUCCESSFUL!")
                        print(f"{B}\n{'*'*30}{W}")
                        time.sleep(.20)
                        print(f"{B}[+]{Y} Attempts          :{O} {i:,} / {total_passwords:,}")
                        time.sleep(.20)
                        print(f"{B}[+]{Y} Time elapsed      :{O} {elapsed} seconds")
                        time.sleep(.20)
                        print(f"{B}[+]{Y} Rate              :{O} {i/elapsed:.1f} attempts/second")
                        time.sleep(.20)
                        print(f"{B}[+]{Y} Key type          :{O} {key_info['type']}")
                        time.sleep(.20)
                        print(f"{B}[+]{Y} Key size          :{O} {key.get_bits()} bits")
                        time.sleep(.20)
                        print(f"{B}[+]{Y} Key fingerprint   :{O} {key.get_fingerprint().hex()}")
                        time.sleep(.20)
                        print(f"{B}[*]{R} Password found    :{P} {password}{W}")
                        time.sleep(.20)
                        key.write_private_key_file(f'{key_path}.decrypted_key.pem')
                        time.sleep(.20)
                        print(f"{B}[+]{Y} key saved to      : {O}{str('/'.join(key_path.split('/')[:-1]))}/decrypted_key.pem{W}")
                        time.sleep(.20)
                        
                        return key
                        
                    except paramiko.ssh_exception.SSHException as e :
                        func = str(self.generate_fake_key())
                        continue
                    except Exception as e:
                        if "password and salt must not be empty" in str(e):
                            continue 
                        print(f"{B}[!]{R} Error        : {O}{e}{W}")
                        return None
            
            if not found:
                elapsed = (datetime.now() - start_time).seconds
                print(f"\n{B}[-]{R}CRACKING FAILED")
                print(f"{Y}\n{'*'*30}")
                print(f"{B}[-] Status          : Password not found in wordlist")
                time.sleep(.20)
                print(f"{B}[-] Total attempts  : {total_passwords:,}")
                time.sleep(.20)
                print(f"{B}[-] Time elapsed    : {elapsed} seconds")
                time.sleep(.20)
                print(f"{B}[-] Average rate    : {total_passwords/elapsed:.1f} attempts/second\n")
                time.sleep(.20)
                print(f"{B}[-] Suggestions     :")
                time.sleep(.20)
                print(f"{R}         1. Try a larger/more targeted wordlist")
                time.sleep(.20)
                print(f"         2. The key might use a different encryption algorithm")
                time.sleep(.20)
                print(f"         3. Check if it's actually a different key type (DSA/ECDSA){W}")
            
            return None

        def control(self):
            print(B+"")
            parser = argparse.ArgumentParser(description="Usage: [OPtion] [arguments] [ -w ] [arguments]")      
            parser.add_argument("-w","--wordlist"  , action=None           ,help ="wordlist of passwords")   
            parser.add_argument("-c","--color"     , action='store_true'   ,help ="set color display off")     
            parser.add_argument("-S","--sshkey"     , action=None   ,help ="set color display off")   
            self.args = parser.parse_args()  
            print(W+"")
            if len(sys.argv)!=1 :
                pass
            else:
                parser.print_help()        
                exit()
                    
if __name__=='__main__':
   SSHCRACK()            