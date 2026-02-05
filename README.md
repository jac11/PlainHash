# 🔐 PlainHash

PlainHash is a password hash cracking tool that performs dictionary
attacks using wordlists.\
It generates hashes for each candidate password and compares them with
the target hash.

PlainHash supports multiple modern and legacy hashing algorithms, salted
hashes, HMAC, Windows hashes, and **SSH private key passphrase
cracking**.

PlainHash is written in **Python 3.9+**

------------------------------------------------------------------------

## ⚠️ Important Notice -- `crypt` Module Removal (Python 3.13)

The `crypt` module used for verifying Unix password hashes was:

-   Deprecated in Python **3.11**
-   Removed in Python **3.13** (PEP 594)

If you are using Python **3.13 or later**, crypt-based hashes may not
work properly.

------------------------------------------------------------------------

## 📦 Requirements

Install required dependencies:

``` bash
pip install pycryptodome
pip install bcrypt
pip install paramiko
```

If you encounter permission or environment errors:

``` bash
pip install pycryptodome --break-system-packages
pip install bcrypt --break-system-packages
pip install paramiko --break-system-packages
```

------------------------------------------------------------------------

## 🧠 Features

-   Fast wordlist-based hash cracking
-   Supports salted and unsalted hashes
-   Supports HMAC authentication hashes
-   Supports Windows NTLM hashes
-   Supports SSH private key passphrase cracking
-   Uses Python secure cryptographic libraries
-   Simple and user-friendly CLI interface
-   Optional colored output

------------------------------------------------------------------------

## 🔑 Supported Hash Algorithms

### Standard Hashes

-   MD4
-   MD5
-   SHA1
-   SHA224
-   SHA256
-   SHA384
-   SHA512
-   SHA3-224
-   SHA3-256
-   SHA3-384
-   SHA3-512
-   BLAKE2b
-   BLAKE2s

------------------------------------------------------------------------

### 🧂 Salted Hash Support

-   MD5-CRYPT
-   SHA1-CRYPT
-   SHA256-CRYPT
-   SHA512-CRYPT
-   bcrypt (2y)
-   yescrypt (v1.1.0)

------------------------------------------------------------------------

### 🪟 Windows Hash Support

-   NTLM (MD4 UTF-16LE)

------------------------------------------------------------------------

### 🔐 HMAC Support

-   HMAC-MD5
-   HMAC-SHA1
-   HMAC-SHA224
-   HMAC-SHA256
-   HMAC-SHA384
-   HMAC-SHA512
-   HMAC-SHA3 (All variants)
-   HMAC-BLAKE2b
-   HMAC-BLAKE2s

------------------------------------------------------------------------

### 🔑 SSH Private Key Support

PlainHash can attempt to crack passphrases protecting encrypted SSH
private keys such as:

-   OpenSSH private keys
-   RSA private keys
-   Encrypted SSH key files

This feature allows PlainHash to act similarly to:

    ssh2john + john

But inside a single tool.

------------------------------------------------------------------------

## 🚀 Installation

``` bash
git clone https://github.com/jac11/PlainHash
cd PlainHash
chmod +x PlainHash.py
```

------------------------------------------------------------------------

## 📖 Usage

### Display Help Menu

``` bash
./PlainHash.py -h
```

------------------------------------------------------------------------

### Crack Single Hash

``` bash
./PlainHash.py -H <hash> -w <wordlist>
```

Example:

``` bash
./PlainHash.py -H dfd5f9139a820075df69d7895015360b76d0360f3d4b77a845689614 -w wordlist.txt
```

------------------------------------------------------------------------

### Crack Hashes From File

``` bash
./PlainHash.py -r hash.txt -w wordlist.txt
```

------------------------------------------------------------------------

### Crack SSH Private Key Passphrase

``` bash
./PlainHash.py -S id_rsa -w wordlist.txt
```

------------------------------------------------------------------------

### Disable Colored Output

``` bash
./PlainHash.py -c off
```

Example:

``` bash
./PlainHash.py -H <hash> -w wordlist.txt -c off
```

------------------------------------------------------------------------

### Show Detailed Tool Information

``` bash
./PlainHash.py -i info
```

------------------------------------------------------------------------

## 📊 How PlainHash Works

1.  Loads target hash or encrypted SSH key
2.  Reads passwords from wordlist
3.  Generates hash for each password
4.  Compares generated hash with target
5.  Displays result when match is found

------------------------------------------------------------------------

## 🧩 Technical Details

PlainHash uses:

-   `hashlib` → Secure hashing
-   `hmac` → Authentication hash support
-   `bcrypt` → bcrypt cracking
-   `pycryptodome` → MD4 + advanced crypto
-   `crypt` → Unix salted hashes (Python \< 3.13)

------------------------------------------------------------------------

## ⚡ Performance Note

Cracking speed depends on:

-   Wordlist size
-   Hash algorithm complexity
-   CPU performance

------------------------------------------------------------------------

## 🧑‍💻 Author

Developed by:

**jac11**\
Ethical Hacker \| Security Researcher \| Developer

GitHub:

    https://github.com/jac11

------------------------------------------------------------------------

## 📬 Contact

    administrator@jacstory.tech

------------------------------------------------------------------------

## ⭐ Contribution & Support

If you like this project:

-   Star the repository ⭐
-   Report bugs
-   Suggest new features
-   Submit pull requests
