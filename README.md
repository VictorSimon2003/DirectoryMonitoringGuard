# DirectoryMonitoringGuard
This code is a C program made for file management and directory monitoring. 

Recursively navigating through several directories, the program examines each file for possible corruption based on permission configurations. It uses a shell script (verify_for_malicious.sh) to determine whether a file is malicious or corrupted.

The file is moved to an isolated directory if it is determined to be dangerous.

In addition, the program takes a snapshot of the directory structure and looks for differences between the most recent snapshot and earlier ones.

It employs semaphores to avoid race conditions and multi-processing to manage several directories at once.
