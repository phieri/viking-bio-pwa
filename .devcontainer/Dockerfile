# Simple Debian/Ubuntu-based devcontainer for Pico W development
FROM mcr.microsoft.com/vscode/devcontainers/base:ubuntu

ARG USERNAME=vscode

# Install system packages and toolchain
RUN apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    curl \
    ca-certificates \
    gcc-arm-none-eabi \
    libnewlib-arm-none-eabi \
    gdb-multiarch \
    openocd \
    python3 \
    python3-pip \
    python3-venv \
    pkg-config \
    libusb-1.0-0-dev \
    usbutils \
  && rm -rf /var/lib/apt/lists/*

# Python tools commonly used by Pico projects
RUN pip3 install --no-cache-dir pyserial pre-commit

# Allow the vscode user access to serial devices (dialout)
RUN groupadd -f dialout || true && usermod -aG dialout ${USERNAME} || true

ENV LANG=C.UTF-8

# Default workdir set by devcontainer.json workspaceFolder at runtime
