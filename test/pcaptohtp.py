import sys
import binascii

# Transforms a pcap into a test file for libhtp
# tshark -Tfields -e tcp.dstport -e tcp.payload -r input.pcap > input.txt
# python pcaptohtp.py input.txt > input.t

f = open(sys.argv[1])
for l in f.readlines():
    portAndPl=l.split()
    if len(portAndPl) == 2:
        # determine request or response based on port
        if portAndPl[0] == "80":
            print(">>>")
        else:
            print("<<<")
        print(binascii.unhexlify(portAndPl[1].replace(":","")))
