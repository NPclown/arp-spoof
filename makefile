LDLIBS=-lpcap

all: send-arp-test

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o iphdr.o icmphdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -pthread -o $@

clean:
	rm -f send-arp-test *.o
