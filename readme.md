~~download [WinDivert binary packages](https://reqrypt.org/windivert.html) extract the zip file.~~


## CONFIG

Then you can config the filter with the file. 
For some case, you dnot need the part for IPv6

## BROADCAST

Now it support to redirect broadcast to specific ip,
Notice only one addr is allow for IPv4 and IPv6

## RUN

Put the `exe` , `filter.cfg` , `WinDivert.dll` at the same dir.
**ADMIN** is required.

to use this function. run the program as follow:

```bash
.\all-in-icmp-win.exe [IPv4 addr] [IPv6 addr]
```

for example:

```bash
.\all-in-icmp-win.exe 10.161.114.514
```

