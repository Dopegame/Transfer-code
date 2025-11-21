```python
from Crypto.PublicKey import RSA
from pwn import *
import math
import base64

e = 65537

while True:
    key = RSA.generate(1024, e=e)
    n = key.n
    p = key.p
    q = key.q
    d = key.d

    phi = (p - 1) * (q - 1)

    if math.gcd(e, phi) == 1:
        break
    else:
        pass

ch = process('/challenge/run')

ch.recvuntil(b"e:")
ch.sendline(f"{e:#x}".encode())

ch.recvuntil(b"n:")
ch.sendline(f"{n:#x}".encode())

ch.recvuntil(b"challenge: ")
challenge = ch.recvline().strip().decode()

ch.recvuntil(b"response:")
s = pow(int(challenge, 16), int(d), int(n))
ch.sendline(f"{s:#x}".encode())

rs = ch.recvall()
b64_ct = rs.split(b"secret ciphertext (b64):")[1].strip()

flag = base64.b64decode(b64_ct)
print(flag.decode('latin1').strip('\x00'))
```
