savedcmd_/home/linh/code/net_sniffer.ko := ld -r -m elf_x86_64 -z noexecstack --build-id=sha1  -T scripts/module.lds -o /home/linh/code/net_sniffer.ko /home/linh/code/net_sniffer.o /home/linh/code/net_sniffer.mod.o;  make -f ./arch/x86/Makefile.postlink /home/linh/code/net_sniffer.ko
