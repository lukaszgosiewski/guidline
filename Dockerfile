FROM ubuntu:20.04

# Avoid timezone prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Update and install essential build tools and Python
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    gdb \
    gcc \
    g++ \
    git \
    make \
    pkg-config \
    valgrind \
    vim \
    nano \
    curl \
    wget \
    # Python and pip
    python3 \
    python3-pip \
    python3-dev \
    # Required for python-magic
    libmagic1 \
    # Common C libraries
    libssl-dev \
    zlib1g-dev \
    # Install Python modules
    && pip3 install --no-cache-dir \
       requests \
       python-magic \
    # Cleanup to reduce image size
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a symbolic link for python command
RUN ln -s /usr/bin/python3 /usr/bin/python

# Create workspace directory
RUN mkdir -p /workspace

# Copy local testproject directory to workspace
COPY testproject /workspace/testproject

# Set working directory to workspace
WORKDIR /workspace

# Set default command to bash
CMD ["/bin/bash"]
