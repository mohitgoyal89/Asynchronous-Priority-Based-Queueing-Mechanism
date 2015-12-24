obj-m += sys_submitjob.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: main submitjob

main: main.c
	gcc -Wall -Werror -lssl main.c -o main

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f main
