# strike back

> A fleet of steam blimps waits the final signal from their commander in order to attack gogglestown kingdom. A recent cyber attack had us thinking if the enemy managed to discover our plans and prepare a counter-attack. Will the fleet get ambused??? 

```

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-11-20 05:05:04 .....       924782       880762  capture.pcap
2021-11-20 05:05:00 .....     10303276       439359  freesteam.dmp
------------------- ----- ------------ ------------  ------------------------

freesteam.dmp: Mini DuMP crash report, 17 streams, Fri Nov 19 20:45:38 2021, 0x469925 type

```

(from windows)

## freesteam.exe

freesteam.exe extracted from wireshark (14kB) by file -> export objects -> HTTP

running [capa](https://github.com/fireeye/capa)
```
+------------------------------------------------------+------------------------------------------------------+
| CAPABILITY                                           | NAMESPACE                                            |
|------------------------------------------------------+------------------------------------------------------|
| write pipe                                           | communication/named-pipe/write                       |
| contain a thread local storage (.tls) section        | executable/pe/section/tls                            |
| read file on Windows                                 | host-interaction/file-system/read                    |
| write file on Windows (2 matches)                    | host-interaction/file-system/write                   |
| get thread local storage value                       | host-interaction/process                             |
| allocate RWX memory (2 matches)                      | host-interaction/process/inject                      |
| terminate process                                    | host-interaction/process/terminate                   |
| create thread (2 matches)                            | host-interaction/thread/create                       |
| link function at runtime on Windows (2 matches)      | linking/runtime-linking                              |
| parse PE header                                      | load-code/pe                                         |
+------------------------------------------------------+------------------------------------------------------+

```

Opening it in Ghidra:

FUN_00402cd0 -> main

UndefinedFunction_00402770 (FUN_00402770) -> executes shellcode


Virustotal:
https://www.virustotal.com/gui/file/4c95b1ec6a108d8ca640f99a8e072614f58b4e602e603d7c73bdb5e77170e327

looks like it's a cobal strike beacon

### looking at shellcode

extracting data from request `/iVd9` (looks like shellcode?)
trying to see if its shellcode:
```
objdump -D -Mintel,x86-64 -b binary -m i386 iVd9.bin | less
iVd9.bin:     file format binary


Disassembly of section .data:

00000000 <.data>:
       0:       fc                      cld    
       1:       e8 05 00 00 00          call   0xb
       6:       92                      xchg   edx,eax
       7:       ea 01 ab 27 eb 27 5f    jmp    0x5f27:0xeb27ab01
       e:       8b 1f                   mov    ebx,DWORD PTR [edi]
      10:       83 c7 04                add    edi,0x4
      13:       8b 0f                   mov    ecx,DWORD PTR [edi]
      15:       31 d9                   xor    ecx,ebx


```


looks promising, since it corroborates well with this article
https://decoded.avast.io/threatintel/decoding-cobalt-strike-understanding-payloads/

looks like x86 (32 bit) payload!

finding some blogs to decode this:
https://newtonpaul.com/analysing-fileless-malware-cobalt-strike-beacon/
https://github.com/dzzie/SCDBG (meh)

download scdbg from https://github.com/dzzie/VS_LIBEMU/blob/master/scdbg.exe

didn find much, but did do all the loadprocaddr

using ghidra to load in the shellcode & analyze

more writeups
https://blog.nviso.eu/2021/10/21/cobalt-strike-using-known-private-keys-to-decrypt-traffic-part-1/
https://blog.nviso.eu/2021/11/17/cobalt-strike-decrypting-obfuscated-traffic-part-4/

parser tool: https://blog.didierstevens.com/2021/10/11/update-1768-py-version-0-0-8/

```
./1768.py -r ./iVd9.bin 
File: ./iVd9.bin
xorkey(chain): 0xb9ce3940
length: 0x00032600
Config found: xorkey b'.' 0x00000000 0x00002ff0
0x0001 payload type                     0x0001 0x0002 0 windows-beacon_http-reverse_http
0x0002 port                             0x0001 0x0002 80
0x0003 sleeptime                        0x0002 0x0004 60000
0x0004 maxgetsize                       0x0002 0x0004 1048576
0x0005 jitter                           0x0001 0x0002 0
0x0006 maxdns                           0x0001 0x0002 255
0x0007 publickey                        0x0003 0x0100 30819f300d06092a864886f70d010101050003818d003081890281810090675223e8a456ebda21cb31552d9f58e675bfa1dabeefbdc3071e5d8d9e263500f9665ce43bc9d0e51aa869b19250d855c8c19f3bac59fc7b4de2164ba4e9327f713436fb283d6cc7326b40755f39209643c1a13bcaaeef082b7a070342254cb2a971c17e43ec095a598678fd02360097fb4a3740d279c8ca61ed3e1b5de96d020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0x0008 server,get-uri                   0x0003 0x0100 '192.168.1.9,/match'
0x0009 useragent                        0x0003 0x0080 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; .NET4.0C)'
0x000a post-uri                         0x0003 0x0040 '/submit.php'
0x000b Malleable_C2_Instructions        0x0003 0x0100 '\x00\x00\x00\x04'
0x000c http_get_header                  0x0003 0x0100
  Cookie
0x000d http_post_header                 0x0003 0x0100
  &Content-Type: application/octet-stream
  id
0x000e SpawnTo                          0x0003 0x0010 (NULL ...)
0x001d spawnto_x86                      0x0003 0x0040 '%windir%\\syswow64\\rundll32.exe'
0x001e spawnto_x64                      0x0003 0x0040 '%windir%\\sysnative\\rundll32.exe'
0x000f pipename                         0x0003 0x0080 (NULL ...)
0x001f CryptoScheme                     0x0001 0x0002 0
0x0013 DNS_Idle                         0x0002 0x0004 0 0.0.0.0
0x0014 DNS_Sleep                        0x0002 0x0004 0
0x001a get-verb                         0x0003 0x0010 'GET'
0x001b post-verb                        0x0003 0x0010 'POST'
0x001c HttpPostChunk                    0x0002 0x0004 0
0x0025 license-id                       0x0002 0x0004 16777216 Stats uniques -> ips/hostnames: 17 publickeys: 17
0x0026 bStageCleanup                    0x0001 0x0002 0
0x0027 bCFGCaution                      0x0001 0x0002 0
0x0036 HostHeader                       0x0003 0x0080 (NULL ...)
0x0032 UsesCookies                      0x0001 0x0002 1
0x0023 proxy_type                       0x0001 0x0002 2 IE settings
0x003a                                  0x0003 0x0080 '\x00\x04'
0x0039                                  0x0003 0x0080 '\x00\x04'
0x0037                                  0x0001 0x0002 0
0x0028 killdate                         0x0002 0x0004 0
0x0029 textSectionEnd                   0x0002 0x0004 0
0x002b process-inject-start-rwx         0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002c process-inject-use-rwx           0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002d process-inject-min_alloc         0x0002 0x0004 0
0x002e process-inject-transform-x86     0x0003 0x0100 (NULL ...)
0x002f process-inject-transform-x64     0x0003 0x0100 (NULL ...)
0x0035 process-inject-stub              0x0003 0x0010 'd\\ÃÂê·Íñ¡T,¬\x13¾\x0c\x07'
0x0033 process-inject-execute           0x0003 0x0080 '\x01\x02\x03\x04'
0x0034 process-inject-allocation-method 0x0001 0x0002 0
0x0000
Guessing Cobalt Strike version: 4.2 (max 0x003a)

```

https://blog.nviso.eu/2021/11/03/cobalt-strike-using-process-memory-to-decrypt-traffic-part-3/

we can use a 64 byte encrypted task data to help extract the encryption keys from memory, but closest thing in pcap is a http response length 68

but there's this in the 1768.py output:
Malleable_C2_Instructions: '\x00\x00\x00\x04' (which correspond to the first 4 bytes in the response, so 68-4=64), maybe this will help?


set `data.len == 68` as wireshark display filter
data:
00000040 <- get rid of the first 4 bytes
317639faf73648274ba8a66d11182283f7fa26fe44b3982a36d80f6ffba4949e5ec759fffb372775d2ac002425547a11ddf2e05c2cb914e09ac033f01db0b60c



```
python3 Beta/cs-extract-key.py -t 317639faf73648274ba8a66d11182283f7fa26fe44b3982a36d80f6ffba4949e5ec759fffb372775d2ac002425547a11ddf2e05c2cb914e09ac033f01db0b60c ./freesteam.dmp 
File: ./freesteam.dmp
Searching for AES and HMAC keys
Searching after sha256\x00 string (0x4048a)
AES key position: 0x00447f81
AES Key:  3ae7f995a2392c86e3fa8b6fbc3d953a
HMAC key position: 0x0044b2a1
HMAC Key: bf2d35c0e9b64bc46e6d513c1d0f6ffe
SHA256 raw key: bf2d35c0e9b64bc46e6d513c1d0f6ffe:3ae7f995a2392c86e3fa8b6fbc3d953a
Searching for raw key
Searching after sha256\x00 string (0x441a49)
AES key position: 0x00447f81
AES Key:  3ae7f995a2392c86e3fa8b6fbc3d953a
HMAC key position: 0x0044b2a1
HMAC Key: bf2d35c0e9b64bc46e6d513c1d0f6ffe
Searching for raw key
```


AAAAANNND.. decrypt!

``python3 Beta/cs-parse-http-traffic.py -e -k bf2d35c0e9b64bc46e6d513c1d0f6ffe:3ae7f995a2392c86e3fa8b6fbc3d953a  -Y'http and frame.number > 47' capture.pcap | tee ./decrypted-traffic.txt``

(use `-e` to extract payloads onto disk)

	file *vir
	payload-00f542efefccd7a89a55c133180d8581.vir: PDF document, version 1.4
	payload-1e4b88220d370c6bc55e213761f7b5ac.vir: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
	payload-2211925feba04566b12e81807ff9c0b4.vir: data
	payload-851cbc5a118178f5c548e573a719d221.vir: PE32+ executable (DLL) (GUI) x86-64, for MS Windows
	payload-b0cfbef2bd9a171b3f48e088b8ae2a99.vir: MS-DOS executable PE32+ executable (DLL) (console) x86-64, for MS Windows
	payload-b25952a4fd6a97bac3ccc8f2c01b906b.vir: ASCII text, with no line terminators

open the PDF:
HTB{Th4nk_g0d_y0u_f0und_1t_0n_T1m3!!!!}
