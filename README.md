# ndd-kernel
Kernel implementation of the NDD congestion control algorithm

## vscode settings
1. Added include paths (https://stackoverflow.com/a/49907377/5039326)
2. This did not work: had to also crate symlink from asm-generic to asm
   (https://stackoverflow.com/a/77616138/5039326)
3. Added compile_commands.json using bear. `bear -- make`. Earlier tried
   scripts/clang-tools/gen_compile_commands.py but that did not work.
