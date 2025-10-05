; kernel.asm -- second stage
BITS 16
ORG 0x7E00

start:
    mov si, kernel_msg
    call print_string

halt:
    hlt       ;puts the CPU in sleep mode
    jmp halt  ; infinite loop

print_string:
    lodsb
    or al, al
    jz done
    mov ah, 0x0E
    int 0x10
    jmp print_string
done:
    ret

kernel_msg db "Kernel: Hello from the Kernel!", 0x0D, 0x0A, 0
