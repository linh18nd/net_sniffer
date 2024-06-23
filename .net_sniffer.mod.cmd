savedcmd_/home/linh/code/net_sniffer.mod := printf '%s\n'   net_sniffer.o | awk '!x[$$0]++ { print("/home/linh/code/"$$0) }' > /home/linh/code/net_sniffer.mod
