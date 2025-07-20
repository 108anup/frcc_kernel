# FRCC kernel module
Kernel implementation of the FRCC congestion control algorithm.

## Compiling and running
```bash
# Compile
make
sudo insmod tcp_frcc.ko

# Run using iperf3
iperf3 -s -p <server port>  # Start iperf3 server
iperf3 -c <server ip> -p <server port> --congestion frcc  # Start iperf3 client
```

## Information

1. Use `sudo set_frcc_params.py` to print, set, or reset FRCC's parameters and
features at runtime while the kernel module is loaded. This will impact new
flows that are started after the script is run.

2. To get clangd language server to recognize dependencies, generate compile_commands.json using:
```bash
sudo apt install bear
bear -- make
```
This will create a `compile_commands.json` file, which can be used by clangd for code completion and navigation. Move this to the `build` directory. You may need to delete some lines in this file. `diff` with the existing `build/compile_commands.json` to see which lines to remove.
