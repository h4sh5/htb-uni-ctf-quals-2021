# upgrades

just use vipermonkey to analyze the pptm. It contains a not-very-obfuscated macro

https://github.com/decalage2/ViperMonkey

`vmonkey ./Upgrades.pptm`

The flag is somewhere in the output

```
...
INFO     calling Function: Array([81, 107, 33, 120, 172, 85, 185, 33], {})
INFO     calling Function: q([81, 107, 33, 120, 172, 85, 185, 33])
INFO     calling Function: Environ('username')
INFO     ACTION: Environ - params ['username'] - Interesting Function Call
INFO     calling Function: Array([154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245, 111, 89, 158, 219, 24, ...)
INFO     calling Function: q([154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245, 111, 89, 158, 219, 24, ...)
INFO     calling Function: StrComp('admin', 'HTB{33zy_VBA_M4CR0_3nC0d1NG}', 0)
INFO     ACTION: Found Heuristic Entry Point - params 'Label1_Click' - 
INFO     evaluating Sub Label1_Click
...
```
