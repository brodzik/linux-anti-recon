obj-m += anti-recon.o

BUILD=/lib/modules/$(shell uname -r)/build/

all:
	$(MAKE) -C $(BUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILD) M=$(PWD) clean

run:
	sudo dmesg --clear
	-sudo rmmod anti-recon
	sudo insmod anti-recon.ko
	-sudo rmmod anti-recon
	sudo dmesg
