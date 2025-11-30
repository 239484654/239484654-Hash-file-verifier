# File Hash Calculator Tool

> [!NOTE]
> This tool stopped updating on August 12, 2025

## Introduction
This tool is a simple desktop application used to calculate the hash values of files or all files in a folder and save the results to an SQLite database. It supports multiple hash algorithms, including MD5, CRC32, SHA - 256, and SHA - 512.

[Chinese version](./README_zhs.md)

## Function Overview
This tool has the following main functions:
1. **Multiple Algorithm Support**: Supports MD5, CRC32, SHA - 256, and SHA - 512 hash algorithms.
2. **File and Folder Processing**: Can process a single file or an entire folder.
3. **File Locking Check**: Before calculating the hash value, it checks if the file is being written to or modified. If so, it skips the file.
4. **Progress Display**: Displays the processing progress when processing a folder.
5. **Result Saving**: Saves the calculated hash values and write times to an SQLite database.

## Interface Description
### Checkboxes
- **MD5**: When checked, the MD5 hash value of the file will be calculated.
- **CRC32**: When checked, the CRC32 hash value of the file will be calculated.
- **SHA - 256**: When checked, the SHA - 256 hash value of the file will be calculated.
- **SHA - 512**: When checked, the SHA - 512 hash value of the file will be calculated.

### Select Path Area
- **Browse Button**: Click to select the file or folder path to be processed.
- **Text Box**: Used to input or display the selected file or folder path.

### Select Save Path Area
- **Browse Button**: Click to select the path to save the database.
- **Text Box**: Used to input or display the path to save the database.

### Finish Button
Click to start calculating the hash values of the files and save the results to the specified database. This button is only enabled when at least one hash algorithm is checked, and both the file or folder path and the database save path are selected.

### Progress Bar
Displays the processing progress when processing a folder.

## Usage Instructions
### Select Hash Algorithms
Check the corresponding hash algorithm checkboxes as needed.

### Select File or Folder Path
Click the "Browse" button to select the file or folder to be processed.

### Select Database Save Path
Click the "Browse" button to select the path to save the database.

### Start Calculation
Click the "Finish" button. The tool will start calculating the hash values of the files and save the results to the specified database. After the calculation is completed, a message box will pop up to display the calculation results.

## Technical Details
### Dependencies
This tool uses the following Python libraries:
- `os`: For file and path operations.
- `hashlib`: For calculating hash values.
- `zlib`: For calculating the CRC32 hash value.
- `sqlite3`: For creating and operating SQLite databases.
- `wx`: For creating the graphical user interface (GUI).
- `datetime`: For recording the write time.
- `psutil`: Not actually used in the code, may be a reserved library.
- `threading`: For multi - threaded processing to avoid interface freezing.
- `ctypes`: For checking if the user has administrator privileges.
- `sys`: For getting command - line arguments.

### Code Structure
- `is_file_locked`: Checks if a file is locked (being written to or modified).
- `calculate_hash`: Calculates the hash value of a file according to the specified algorithm.
- `process_files`: Processes files or folders, calculates hash values, and saves them to the database.
- `HashCalculatorGUI`: The graphical user interface class, including interface elements and event handling methods.
- `is_admin`: Checks if the user has administrator privileges.

## Notes
- Make sure you have sufficient permissions to access the files or folders to be processed and the path to save the database.
- If a file is being written to or modified, the tool will skip the hash calculation for that file.

We hope this instruction manual will help you use this tool better. If you have any questions or suggestions, please feel free to provide feedback.