+++
title = "Intercepting Android's Encrypted Traffic: Hooking BoringSSL with friTap"
date = 2025-02-28T17:43:13+01:00
description = "How to use BoringSecretHunter to facilitate hooking BoringSSL with friTap"
author = "Daniel Baier"
tags = ["TLS", "TLS Decryption"]
keywords = ["TLS", "friTap", "TLS Decryption"]
toc = false
showFullContent = false
draft = false
+++

## Introduction

[friTap](https://github.com/fkie-cad/friTap/) is a powerful tool designed to assist security researchers in analyzing network traffic protected by SSL/TLS. By automating key extraction and decrypting traffic at runtime, friTap simplifies complex workflows, making it especially valuable for malware analysis and the investigation of data privacy practices in mobile and desktop applications. For more technical background, see [this in-depth post](https://lolcads.github.io/posts/2022/08/fritap/) or explore the source code directly on GitHub.

A core feature of friTap is its ability to extract TLS session keys across various platforms and TLS implementations, allowing seamless integration into traffic analysis pipelines using tools like Wireshark, Zeek and others. However, certain situations—such as statically linked or stripped binaries—pose additional challenges for dynamic instrumentation.

This is especially common in Android applications using **Cronet** (`libcronet.so`) or **Flutter** (`libflutter.so`), where **BoringSSL** is statically linked and stripped of symbols. In such cases, direct function hooking becomes infeasible without symbol information. Fortunately, friTap supports a technique known as **hooking by byte patterns**, enabling reliable function interception based on instruction-level signatures.

## Hooking via Byte Patterns

When symbol resolution is not possible due to static linking or symbol stripping, friTap supports hooking functions via byte patterns. This approach involves scanning the memory of the target process for predefined instruction sequences that uniquely identify key TLS-related functions.

You can provide friTap with a JSON file containing these byte patterns using the `--patterns <byte-pattern-file.json>` option. Each pattern is categorized by its role in the TLS handshake or encryption flow, including:

- `Dump-Keys`  
- `Install-Key-Log-Callback`  
- `KeyLogCallback-Function`  
- `SSL_Read`  
- `SSL_Write`  

Each category can define both a **primary** and a **fallback** pattern to increase reliability across different binary versions and architectures.

Here's an example JSON snippet for the `Dump-Keys` category:

```json
"Dump-Keys": {
  "primary": "AA BB CC DD EE FF ...", 
  "fallback": "FF EE DD CC BB AA ..."
}
```

- **Primary Pattern**: The preferred pattern for identifying the target function.  
- **Fallback Pattern**: A backup used when the primary fails to match.

The `Dump-Keys` category is particularly important, as it targets functions responsible for logging or exporting TLS session keys. Once matched, friTap uses internal logic to parse key material directly from memory, enabling live decryption of encrypted sessions.

## Automating Pattern Extraction with BoringSecretHunter

To streamline the process of identifying byte patterns in statically linked BoringSSL binaries, we developed a companion tool: [**BoringSecretHunter**](https://github.com/monkeywave/BoringSecretHunter). This Ghidra-based analysis utility scans the binary for the `ssl_log_secret()` function—commonly used internally in BoringSSL for logging key material—and outputs a ready-to-use byte pattern for hooking with friTap.

BoringSecretHunter is especially useful for analyzing stripped binaries on Android, where traditional reverse engineering techniques are time-consuming. Once the relevant pattern is identified, you can simply feed it to friTap and begin live TLS key extraction—even in challenging CTF or malware sandboxing environments.

## Building BoringSecretHunter

To get started, build the Docker image provided in the repository. Run the following command from the project root:

```bash
docker build -t boringsecrethunter .
```

## Usage

Once the Docker image is built, you can analyze a target binary by mounting it into the container. For example, to scan a statically linked Cronet library located in the `binary/` folder:

```bash
docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  boringsecrethunter
```

You should see output similar to the following:

```bash
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter


Analyzing libcronet.113.0.5672.61.so...
        BoringSecretHunter
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    
Identifying the ssl_log_secret() function for extracting key material using Frida.
Version: 1.0.2 by Daniel Baier

[*] Start analyzing binary libcronet.113.0.5672.61.so (CPU Architecture: AARCH64). This might take a while ...


[*] Target function identified (ssl_log_secret):

Function label: FUN_00493BB0
Function offset: 00493BB0 (0X493BB0)
Byte pattern for frida (friTap): 3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 C8 07 00 B4
```
Once this pattern is extracted, you’re ready to integrate it into friTap for live decryption.

## friTap

## Example for a shared object not supported by friTap




![Invocation of the keylog callback](./images/invocation_of_keylog_callback.png "IDA Pro Screenshot")