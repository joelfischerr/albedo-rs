FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    wget \
    sudo \
    unzip \
    libmodsecurity-dev\
    libmodsecurity3t64\
    modsecurity-crs\
    pkg-config\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# The 'ubuntu' user (UID 1000) already exists in ubuntu:24.04.
# We just need to give it passwordless sudo access.
ARG USERNAME=ubuntu

RUN echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Set the default user to the existing 'ubuntu' user
USER $USERNAME

# Get Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc
