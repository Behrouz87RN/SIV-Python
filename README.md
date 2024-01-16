

# System Integrity Verifier (SIV) 


## 1. Introduction
The System Integrity Verifier (SIV) is a Python 3-based tool designed for System Integrity Verification. This assignment focuses on creating a verification file in two modes: Initiation and Verification. In the Initiation mode, the SIV captures the state of all files and directories in a given directory and creates a verification file. In Verification mode, the SIV checks for changes in the directory based on the created verification file and reports any modifications to a separate report file.

## 2. Design and Implementation
### Verification File Format
The verification file contains 8 values separated by commas, each entry separated by a new line. These values include:
1. File type
2. Path name (full path of the file)
3. File size
4. File owner
5. File group
6. File access rights (in Octal)
7. Last modification date and time
8. File hash (hash of the file's content)

### Verification of Changes
To verify changes, the program loads the user-specified verification file, separates the data into an array, and then compares it with the current files on the system. Mismatches result in a report detailing the changes, including file additions, deletions, and modifications.

### Programming Language
Python 3 was chosen for its development speed, making it suitable for this testing-focused program. While performance is not the primary concern, Python provides a balance between ease of development and reasonable execution speed.

## 3. Usage
### Initialization Mode
Run the initialization mode with the following command:
```bash
./siv.py -i -D <monitored-directory> -V <verification-file> -R <report-file> -H <hash>
```
Example:
```bash
./siv.py -i -D /var/log -V db.csv -R report-1.txt -H sha1
```

### Verification Mode
Run the verification mode with the following command:
```bash
./siv.py -v -D <monitored-directory> -V <verification-file> -R <report-file>
```
Example:
```bash
./siv.py -v -D /var/log -V db.csv -R report-2.txt
```

### Help Mode
Run the help mode with the following command:
```bash
./siv.py -h
```

Flags:
- **-D:** Directory to be monitored
- **-V:** Name of the verification file
- **-R:** Name of the report file
- **-H:** Hash algorithm (sha1 or md5)

**Note:** Flags should be written in uppercase.

## 4. Limitations
There are no known limitations in the code, and it has been tested successfully on Ubuntu 22.04. The program has been validated against provided Python tests and demonstrated compatibility with the Testsiv video data.
