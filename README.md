# Directory Monitoring Guard

This code is a C program designed for file management and directory monitoring. 

## Features

- **Recursive Directory Navigation**: The program recursively navigates through several directories, examining each file for possible corruption based on permission configurations.
- **Malicious File Verification**: It uses a shell script (`verify_for_malicious.sh`) to determine whether a file is malicious or corrupted.
- **Isolated Directory Management**: If a file is determined to be dangerous, it is moved to an isolated directory.
- **Directory Structure Snapshot**: The program takes a snapshot of the directory structure and compares it with previous snapshots to identify any differences.
- **Concurrency Management**: It employs semaphores to avoid race conditions and uses multi-processing to manage several directories simultaneously.

