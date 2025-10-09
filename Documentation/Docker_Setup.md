# Docker Setup – Secure Boot Project

## Overview

This setup moves our Secure Boot project into a Docker-based environment so everyone uses the same dependencies and build tools.

---

## 1. Check You’re on the Right Branch

Make sure you’re on the `docker-setup` branch.

### Option 1 – Command Line

```bash
git branch
```

If you see:

```
* docker-setup
  main
  dev
```

you’re already in the right branch.

If not:

```bash
git checkout docker-setup
```

### Option 2 – GitHub Desktop

1. Open the repo in GitHub Desktop
2. Click **Current Branch** at the top
3. Select **docker-setup** from the list
4. Wait for it to switch before continuing

---

## 2. Build the Docker Image

Go to the `src` folder (where the Dockerfile is) and run:

```bash
docker build -t secureboot-env .
```

This installs everything we need:

* gcc, openssl, qemu
* dos2unix for fixing line endings
* other build and debug tools

---

## 3. Run the Container

Start a container and mount the current folder:

```bash
docker run -it --rm -v "$(pwd):/workspace" secureboot-env
```

This gives you a clean build environment. The `/workspace` folder inside the container maps to your local project, so everything you build stays in your local files too.

---

## 4. Build the Project

Inside the container, run:

```bash
bash ./run_build.sh
```

That script:

* Fixes line endings on `.sh` files
* Runs `build.sh`
* Builds bootloaders, generates keys, and creates signatures

---

## 5. Exit the Container

When you’re done:

```bash
exit
```

All your build outputs stay in your local `src` directory.

---

## 6. Rebuild the Image (if Dockerfile Changes)

If the Dockerfile gets updated or dependencies change:

```bash
docker build -t secureboot-env .
```

---

## Notes

* Everyone only needs to build the Docker image once.
* Make sure you’re on the `docker-setup` branch before testing or building.
* No need to install dependencies in WSL — Docker already has everything.
* Line endings from Windows are automatically fixed when you build.

