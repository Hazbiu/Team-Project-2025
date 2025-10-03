                                                         Initial Setup

1.  Clone the repository 
        https://github.com/Hazbiu/Team-Project-2025.git

2.  Install Ubuntu in WSL Open PowerShell and run
         wsl --install Ubuntu

3.  Update and Install Required Packages Once Ubuntu is installed, open WSL and run 
        sudo apt update 
        sudo apt install nasm qemu-system qemu-utils 
        sudo apt install dos2unix -y

4.  Make the script executable 
        chmod +x build.sh

5.  Windows Line Endings 
        dos2unix build.sh

6.  Build and Run 
        ./build.sh

If everything is set up correctly, QEMU will display:

    Bootloader: Hello from Simple OS! 
    Kernel: Hello from the Kernel!

### If 5. doesn't work, try :
        bash build.sh
