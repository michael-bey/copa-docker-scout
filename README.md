# 🏭 Docker Scout Scanner Plugin for Copacetic

This is a scanner plugin for [Copacetic](https://github.com/project-copacetic/copacetic) that processes Docker Scout vulnerability reports and enables automatic patching of container images.

## Overview

This plugin:
- Processes Docker Scout vulnerability reports
- Maps package names to their Debian equivalents
- Filters out irrelevant vulnerabilities based on their descriptions
- Generates a structured report for Copa to patch images

## Prerequisites

The following tools are required to build and run this plugin:

- `git`: for cloning this repo
- `Go`: for building the plugin
- `make`: for building the binary
- `docker`: for running Docker Scout and Copa
- `copa`: the Copacetic CLI tool
- `buildkit`: for image patching (see BuildKit Setup below)

## BuildKit Setup

Copa requires BuildKit for patching images. You can run BuildKit in a container:

```shell
# Stop any existing BuildKit container
docker stop buildkitd || true
docker rm buildkitd || true

# Start BuildKit with proper configuration
docker run -d --name buildkitd --privileged \
--restart always \
-v /var/run/docker.sock:/var/run/docker.sock \
moby/buildkit:v0.12.4
```

## Building

```shell
# Clone this repo
git clone https://github.com/project-copacetic/scanner-plugin-template.git

# Change directory to the repo
cd scanner-plugin-template

# Build the copa-docker-scout binary
make

# Add copa-docker-scout binary to PATH
export PATH=$PATH:$(pwd)/dist/$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m)/release/
```

## Usage

### 1. Generate a Docker Scout Report

First, generate a vulnerability report using Docker Scout:

```shell
# Scan an image with Docker Scout
docker scout cves nginx:1.21.6 --format gitlab --output nginx1.26.1.json
```

### 2. Process and Patch

There are two ways to use the plugin with Copa:

#### Option A: Direct Piping (Recommended)
```shell
# Process the report and pipe directly to Copa
copa-docker-scout nginx1.26.1.json | \
copa patch --scanner docker-scout --image nginx:1.21.6 \
-t nginx-1.21.6-patched --addr docker-container://buildkitd -
```

#### Option B: Two-Step Process
```shell
# First, generate the processed report
copa-docker-scout nginx1.26.1.json > processed-report.json

# Then use Copa to patch the image
copa patch --scanner docker-scout --image nginx:1.21.6 \
-r processed-report.json -t nginx-1.21.6-patched \
--addr docker-container://buildkitd
```

### 3. Verify Patching

After patching, you can verify the results:

```shell
# Check if the patched image exists
docker images | grep nginx-1.21.6-patched

# Scan the patched image for remaining vulnerabilities
docker scout cves nginx:nginx-1.21.6-patched
```

## Test Cases

The repository includes a test case using `nginx-epss.json`, which demonstrates:

1. Processing of various vulnerability types:
   - CVEs with different severity levels
   - Vulnerabilities with special status (ignored, rejected, etc.)
   - Multiple vulnerabilities for the same package

2. Package name mapping:
   - Direct mappings (e.g., `openssl` → `openssl`)
   - Complex mappings (e.g., `gnutls28` → `libgnutls30`)
   - Fallback to original names when no mapping exists

3. Version handling:
   - Installed version extraction
   - Fixed version identification
   - Version comparison logic

## Implementation Details

### Package Mapping

The plugin includes mappings for common Debian packages. Some examples:
- `glibc` → `libc6`
- `krb5` → `libkrb5-3`
- `libwebp` → `libwebp6`
- `tiff` → `libtiff5`

### Vulnerability Filtering

The plugin skips vulnerabilities that:
- Are marked with `<no-dsa>`
- Are marked with `<unfixed>`
- Are marked with `<ignored>`
- Contain `REJECT` in their description

### Output Format

The plugin generates a structured JSON report containing:
- Operating system information (type, version, architecture)
- Package details (name, installed version, fixed version)
- Vulnerability IDs

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.