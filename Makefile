obj-m += anti-recon.o

BUILD=/lib/modules/$(shell uname -r)/build/

all:
	$(MAKE) -C $(BUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILD) M=$(PWD) clean
	-sudo rmmod anti-recon
	sudo dmesg --clear

run:
	-sudo rmmod anti-recon
	sudo dmesg --clear
	sudo insmod anti-recon.ko
	sudo dmesg
