# Microsoft AES-256 File Encryption

This C++ example allows you to encrypt & decrypt your files with a password.

### Usage:
```
MS-AES-256-FE.exe <filename> <password> <lock/unlock>
```

### Encrypt / Lock a file:
```
MS-AES-256-FE.exe ./test.txt hello-world lock
```
This will create ./test.txt.locked 


### Decrypt / Unlock a file:
```
MS-AES-256-FE.exe ./test.txt.locked hello-world unlock
```
This creates ./test.txt.locked.unlocked
