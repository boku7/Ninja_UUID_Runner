#!usr/bin/python3

from uuid import UUID
import sys

if len(sys.argv) < 2:
    print("Usage: %s <shellcode_file>" % sys.argv[0])
    sys.exit(1) 

with open(sys.argv[1], "rb") as f:
    chunk = f.read(16)
    print("{}const char* uuids[] =".format(' '*4))
    print("    {")
    while chunk:
        if len(chunk) < 16:
            padding = 16 - len(chunk)
            chunk = chunk + (b"\x90" * padding)
            print("{}\"{}\"".format(' '*8,UUID(bytes_le=chunk)))
            break
        print("{}\"{}\",".format(' '*8,UUID(bytes_le=chunk)))
        chunk = f.read(16)
    print("    };")
