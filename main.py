import ctypes
import psutil

process = psutil.Process(pid)

k_handle = ctypes.WinDLL("Kernel32.dll")
handle = k_handle.OpenProcess(0x0010, False, pid)

mem = k_handle.VirtualAllocEx(handle, None, 4096, 0x1000 | 0x2000, 0x40)

pattern = b"\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x48\x08\x48\x8B\x01\xFF\x90\x00\x00\x00\x00"
result = ctypes.create_string_buffer(4)
k_handle.ReadProcessMemory(handle, mem, pattern, len(pattern), None)
offset = 0
for i in range(len(pattern) - 4):
    if pattern[i:i+4] == b"\x00\x00\x00\x00":
        offset = i
        break

vtable_address = struct.unpack("I", result[offset:offset+4])[0]

class_name_pattern = b"UWorld\x00"
k_handle.ReadProcessMemory(handle, vtable_address - 0x1000, class_name_pattern, len(class_name_pattern), None)

if class_name_pattern in result.value:
    print("UWorld object found at vtable address:", hex(vtable_address))
else:
    print("UWorld object not found.")

k_handle.VirtualFreeEx(handle, mem, 0, 0x8000)
