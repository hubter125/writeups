Looking at the source code, several key mechanics stand out:

* **Vulnerable Copy:** The `vuln()` function uses `strcpy()` to copy user input into `buf2`, a stack buffer allocated for only 16 bytes.
* **Inverted Win Condition:** Typically, a segmentation fault terminates the process, but here `sigsegv_handler()` catches `SIGSEGV` and prints the flag directly before exiting[cite: 1].
* **Objective:** Any payload that induces an unhandled memory violation (such as corrupting saved frame pointers or hijacking the saved return address to an unmapped region) triggers the signal handler and prints the flag[cite: 1].

### Stack Layout & Overwrite Mechanics

On 32-bit x86 architectures, the stack frame for `vuln()` arranges local variables and control data sequentially:

| Memory Address | Component | Size |
| :--- | :--- | :--- |
| `Higher Memory` | **Saved Return Address (`EIP`)** | 4 bytes |
| `↓` | **Saved Base Pointer (`EBP`)** | 4 bytes |
| `↓` | **Compiler Padding / Alignment** | Implementation-dependent |
| `Lower Memory` | **`buf2` Buffer** | 16 bytes[cite: 1] |

Writing beyond 16 bytes spills into stack metadata:
1. **16 bytes:** Fills `buf2` completely[cite: 1].
2. **Padding + Saved EBP (4 bytes):** Overwrites compiler padding and overwrites the saved base pointer.
3. **The 21st Byte (`\0`):** Because `strcpy()` appends an implicit null byte (`\0`)[cite: 1], a 20-character input actually writes 21 bytes, corrupting the least significant byte of the saved return address (`EIP`) and triggering `SIGSEGV` when `vuln()` returns[cite: 1].

### Solution Script

After verifying that this works locally, we can use pwntools to automate grabbing the flag remotely, grabbing the flag `picoCTF{ov3rfl0ws_ar3nt_that_bad_c5ca6248}`

```python
from pwn import *

host = "saturn.picoctf.net"
port = 12345

io = remote(host, port)

io.sendlineafter(b": ", b"A" * 20)

flag = io.recvall().decode()
print(flag)
```
