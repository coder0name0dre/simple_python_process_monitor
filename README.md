# Simple Python Process Monitor

This project is a Python script that monitors running processes on your computer and detects **simple suspicious activity.**

This script checks for things like:
 - Processes with names such as `cmd.exe`, `powershell.exe`, `sh`, `bash`
 - Programs running from unusual folders like **Downkoads** or **Temp**
 - Processes using **high CPU**
 - Anything that triggerds one of these checks gets logged into **CSV file**

---

## Features

- Scans all running processes
- Detects simple signs of unusual activity
- Displays alerts in the terminal
- Logs suspicious processes to a CSV file

---

## Requirements

- Pythion 3.7+
- Library: Psutil:
```
pip install psutil
```

This scriopt works on:
- Windows
- macOS
- Linux

For best results, run with Administrator/root permissions so the script can read full process details.

---

## Usage

1. Clone the repo:
```
git clone https://github.com/coder0name0dre/simple_python_process_monitor.git
cd simple_python_process_monitor
```

2. Run it:

**Windows**

Open Comand Prompt (Admin):

```
python simple_python_process_monitor.py
```

**macOS / Linux**

Run with sudo for best visibility:

```
sudo python3 simple_python_process_monitor.py
```

3. Stop the monitor anytime using:

```
CTRL + C
```

---

## What Gets Logged?

The script creates a file called:

`suspicious_processes.csv`

Each suspicious entry adds a row containing:

**timestamp**:       When the scan was performed

**pid**:             Process ID

**process_name**:    Name of the executable

**username**:        User that launched the process

**exe_path**:        Full path to the executable

**cmdline**:         Full command-line arguments

**cpu_percent**:     CPU usage %

**memory_mb**:       Memory usage in MB

**reasons**:         Why it was flagged (one or more rules)
