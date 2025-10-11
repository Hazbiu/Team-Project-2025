# WSL Setup Guide for Project Scripts

This guide explains how to properly set up WSL (Windows Subsystem for Linux) so that project scripts like `run_build.sh` and `build.sh` run without errors such as:
````markdown

-bash: ./build.sh: cannot execute: required file not found
````

By following these steps, you’ll make sure your helper scripts work smoothly inside WSL — without Windows line-ending or permission issues.

---

## Create a folder for local WSL helpers

Open your WSL terminal and run:

```bash
mkdir -p ~/wsl_helpers
```

---

## Move the helper script to your local WSL helpers folder

```bash
mv /mnt/.../.../Team-Project-2025/src/run_build.sh ~/wsl_helpers/
```

> **Note:** Replace the `...` with your actual path.
> `/mnt/*driver*/...` is your Windows path.
> `~/wsl_helpers/` is your Linux home directory.

---

## Make the script executable

```bash
chmod +x ~/wsl_helpers/run_build.sh
```

---

## Open your shell configuration file

```bash
nano ~/.bashrc
```

---

## Add the helpers folder to your PATH

At the very end of `.bashrc`, add:

```bash
export PATH="$HOME/wsl_helpers:$PATH"
```

---

## Reload your shell configuration

```bash
source ~/.bashrc
```

---

## Test the script

```bash
run_build.sh
```

---
## Troubleshooting -bash: ./build.sh: cannot execute: required file not found

If you still get an error that the file is missing, this is because the run_build.sh file we coppied from github to Wsl_helpers has windows style line endings, to fix this (this fix is only to be done once if necessary):

Navigate to wsl_helpers file:
```bash
cd ~/wsl_helpers/
```
List the content to double check run_build.sh has been properly coppied, and then finally run:
```bash
unix2dos run_build.sh
```
This will fix line endings issue for the run_build.sh file thats being kept localy in WSL.

## Troubleshooting: Missing OpenSSL headers

If you see an error like this while running `./build.sh`:

```text
primary_bootloader.c:3:10: fatal error: openssl/evp.h: No such file or directory
   3 | #include <openssl/evp.h>
     |          ^~~~~~~~~~~~~~~
compilation terminated.
```

Install the OpenSSL development library:

```bash
sudo apt update
sudo apt install -y libssl-dev
```

Then rerun your build:

```bash
./build.sh
```

---

## Full Test — Simulate a fresh start

Navigate to your project and reset line endings to simulate a Windows clone:

```bash
cd /mnt/c/Programming/Team-Project-2025/src
unix2dos *.sh 2>/dev/null || echo "unix2dos not installed — skip"
```

Now test that the problem appears again:

```bash
./build.sh
```

You should see:

```bash
-bash: ./build.sh: cannot execute: required file not found
```

---

## Run helper setup

```bash
run_build.sh
```

It should:

* Install `dos2unix` if missing
* Convert all `.sh` files in the project to Unix line endings
* Make them executable


If it runs without errors, everything is configured correctly.


## Example: Using `run_build.sh` inside your project folder

When inside your project’s source directory in Windows:

```bash
C:\Users\Mateja\Documents\GitHub\Team-Project-2025\src>wsl
mateja@MatejaSurfaceGo:/mnt/c/Users/Mateja/Documents/GitHub/Team-Project-2025/src$ run_build.sh
============================================
 WSL Helper: Ensure dos2unix & Run build.sh
============================================
dos2unix already installed.
Converting all .sh files to Unix line endings...
dos2unix: converting file ./build.sh to Unix format...
dos2unix: converting file ./run_build.sh to Unix format...
Making all .sh files executable...
Running build.sh...
============================================
 Secure Boot Chain Build & Execution Script
============================================
[1/10] Using project root: /mnt/c/Users/Mateja/Documents/GitHub/Team-Project-2025/src
[1/10] Boot directory:     /mnt/c/Users/Mateja/Documents/GitHub/Team-Project-2025/src/boot
[1/10] Keys directory:     /mnt/c/Users/Mateja/Documents/GitHub/Team-Project-2025/src/keys

[sudo] password for mateja:
````

---

## `run_build.sh` Script Reference

Below is the full helper script that automates the setup and build process:

```bash
#!/bin/bash
set -e

echo "============================================"
echo " WSL Helper: Ensure dos2unix & Run build.sh "
echo "============================================"

# --- Check and install dos2unix if missing ---
if ! command -v dos2unix &> /dev/null; then
    echo "dos2unix not found. Installing..."
    sudo apt update -y
    sudo apt install -y dos2unix
else
    echo "dos2unix already installed."
fi

# --- Convert all .sh files to Unix line endings ---
echo "Converting all .sh files to Unix line endings..."
find . -type f -name "*.sh" -exec dos2unix {} \;

# --- Make all .sh files executable ---
echo "Making all .sh files executable..."
find . -type f -name "*.sh" -exec chmod +x {} \;

# --- Run build.sh ---
echo "Running build.sh..."
./build.sh
```

---

## Why We Use `run_build.sh`

We’ll be using `run_build.sh` from now on because it automates all the setup steps needed for reliable builds inside WSL.
Specifically, it:

* Ensures `dos2unix` is installed
* Fixes Windows-style line endings in all shell scripts
* Applies executable permissions to every `.sh` file
* Finally, runs the main `build.sh` script that compiles the project or kernel components

In short, `run_build.sh` guarantees that your build environment is always consistent, preventing common WSL issues like line-ending errors or permission problems — so you can just run one command and build everything smoothly.


