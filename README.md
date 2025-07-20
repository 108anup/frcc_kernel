# FRCC kernel module
Kernel implementation of the FRCC congestion control algorithm.

```bash
# Compile
make
sudo insmod tcp_frcc.ko

# Run using iperf3
iperf3 -s -p <server port>  # Start iperf3 server
iperf3 -c <server ip> -p <server port> --congestion frcc  # Start iperf3 client
```
