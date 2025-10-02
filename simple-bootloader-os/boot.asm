; boot.asm -- our bootloader (512 bytes)
BITS 16
ORG 0x7C00             ; BIOS loads boot sector here

start:
    ; Print message
    mov si, boot_msg
    call print_string

    ; Load kernel (next sector) at 0x7E00
    mov ah, 0x02        ; BIOS read sectors
    mov al, 1           ; read 1 sector
    mov ch, 0           ; cylinder
    mov cl, 2           ; sector (2nd sector, since boot sector = 1st)
    mov dh, 0           ; head
    mov dl, 0x00        ; drive (floppy)
    mov bx, 0x7E00      ; load address
    int 0x13

    ; Jump to kernel
    jmp 0x0000:0x7E00

print_string:
    lodsb
    or al, al
    jz done
    mov ah, 0x0E
    int 0x10
    jmp print_string
done:
    ret

boot_msg db "Bootloader: Hello from Simple OS!", 0x0D, 0x0A, 0

times 510-($-$$) db 0   ; pad to 510 bytes
dw 0xAA55               ; boot sector signature
