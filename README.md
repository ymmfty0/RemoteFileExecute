# Remote PE Execute 

This POC (Proof of Concept) is a technical demonstration of a method to bypass the Windows Defender protection. It accomplishes this by using a mechanism to transfer a Portable Executable (PE) executable file over TCP and then executing that file directly in system memory.

How it works:
1. Delivery of PE file via TCP:
  - A PE file (Portable Executable format executable file) is a program module that can be executed by the system.
  - The file is transmitted over the network via TCP protocol to avoid detection during transmission using encryption or data concealment.
2. Execution of the file in memory:
  - After successful transfer of a PE file, execution of the file is performed directly in the system's memory, bypassing the step of saving to disk.


This POC is not intended for malicious use, but rather to illustrate potential threats and weaknesses in existing defenses in order to improve security and develop more effective security measures.

# POC 
https://vimeo.com/888657998

# Techinal details 

Compiler: Microsoft (R) C/C++ version 19.37.32822 for x64

Windows Version:

Edition Windows 11 Pro Version 22H2 OS build 22621.1702 Experience Windows Feature Experience Pack 1000.22641.1000.0

# Usage 

To use it, we first need to compile the project using Visual Studio

Then run the python script on our server

```python
python server.py --lport 4443 --pe havoc.exe
```

After that we upload our compiled exe file to the victim machine. 

Wait for execution.
