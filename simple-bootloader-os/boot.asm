; boot.asm -- our bootloader (512 bytes)
BITS 16  ;16-bit real mode code
ORG 0x7C00             ; address in RAM, where BIOS loads the boot sector

start:
    ; Print message
    mov si, boot_msg  ; load SI with the address of boot_msg
    call print_string

    ; Load kernel at 0x7E00
    mov ah, 0x02        ; BIOS read sectors
    mov al, 1           ; no of sectors to read(1)
    mov ch, 0           ; cylinder no
    mov cl, 2           ; sector no (since boot sector = 1st)
    mov dh, 0           ; head no
    mov dl, 0x00        ; drive no(floppy A:)
    mov bx, 0x7E00      ; load address
    int 0x13            ; BIOS`s disc service interrupt


    jmp 0x0000:0x7E00   ; Jump to kernel

print_string:
    lodsb         ;loads the byte at DS:SI into AL and increments SI
    or al, al     ; checks AL content
    jz done       ; jump if zero
    mov ah, 0x0E  ;teletype Output function.
    int 0x10      ; BIOS video services interrupt
    jmp print_string
done:
    ret

boot_msg db "Bootloader: Hello from Simple OS!", 0x0D, 0x0A, 0

times 510-($-$$) db 0   ; pad to 510 bytes
dw 0xAA55               ; last 2 bytes of the boot sector
