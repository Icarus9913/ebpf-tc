# eBPF tc demo

This is a testing demo that implements a simple DNAT with eBPF TC(Traffic control). 
It will switch the network packet destination IP addr from `10.0.2.11` to `10.6.183.22`. 

Note: This project is an extension by `ArthurChiao` eBPF learning, you can check [ArthurChiao's blog](https://github.com/ArthurChiao/arthurchiao.github.io)

## Preparation

Start a nginx in `10.6.183.22` Node with port `6666`.

You can use docker to start up a nginx container and map the port.

   ```text
   docker run --rm -d -p 6666:80 --name my_nginx nginx
   ```

## How to run

1. compile `dnat-demo.c` with `clang`:

    ```text
    clang -O2 -Wall -c dnat-demo.c -target bpf -o dnat-demo.o
    ```

2. add tc queuing discipline (egress and ingress buffer) for NIC `ens160`:

   ```text
   tc qdisc del dev ens160 clsact 2>&1 >/dev/null
   tc qdisc add dev ens160 clsact
   ```

3. load bpf code into the tc egress and ingress hook respectively:

   ```text
   tc filter add dev ens160 egress bpf da obj dnat-demo.o sec egress
   tc filter add dev ens160 ingress bpf da obj dnat-demo.o sec ingress
   ```

4. show info:

   ```text
   tc filter show dev ens160 egress
   tc filter show dev ens160 ingress
   ```
   
5. test run:

   ```text
   curl 10.0.2.11:6666
   ```

6. clean up:

   ```text
   tc qdisc del dev ens160 clsact 2>&1 >/dev/null
   ```

7. check the logs:

   ```text
   cat /sys/kernel/debug/tracing/trace_pipe
   ```
