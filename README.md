# hfioquake3_DoS

ioquake3 engine is vulnerable to a remotely exploitable off-by-one overflow due 
to a miscalculated array index within the privileged admin console command banaddr. 
Attacker needs the rcon password to exploit this vulnerability. 

The vulnerability is present on line 955 of sv_ccmds.c due to a miscalcuation of
array index (off-by-one). If an attacker adds more than 1024 IP addresses using 
the "banaddr" command which calls "SV_AddBanToList", an index used to access the 
serverBans arrray is miscalculated and writes past the bounds of the array. The 
conditional check on line 945 should test that serverBansCount is not greater than 
1023 to prevent exploitation of this issue.

A proof-of-concept exploit has been created to exploit this flaw which will result 
in SIGSEGV in the remote Openarena engine server which can be used by an attacker 
in posession of the rcon password. To exploit this issue without the rcon password
an attacker needs the server admin to ban 1024 unique IP addresses, which can be 
semi-automated by sending profanities on servers that have auto-banning enabled. 

Crash (aarch64)
===============
```
Program received signal SIGSEGV, Segmentation fault.
0x004106a4 in SV_SendClientMessages ()
(gdb) x/i $pc
=> 0x4106a4 <SV_SendClientMessages+140>:        ldr     r0, [r2, #32]
(gdb) i r $r0
r0             0x1                 1
(gdb) i r $r2
r2             0x4                 4
(gdb) bt
#0  0x004106a4 in SV_SendClientMessages ()
#1  0x0040f28e in SV_Frame ()
#2  0x00421912 in Com_Frame ()
#3  0x00402eb0 in main ()
```
