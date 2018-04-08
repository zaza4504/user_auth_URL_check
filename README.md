# New Document

# user_auth_URL_check

This is the sample code to perform remote user authentication followed by a message(ex:URL) validation, and UDP traffic acknowledge is also partialy demonstrated

### The Protocol
#### The protocol is sample as following 

In the TCP user authentication phase:  
client --- A0 --> server  
client <-- A1 --- server  
client --- A2 --> server  
client <-- A3 --- server  

In the message (ex: URL) validation phase:

client --- [message] --> server  
client <-- [reply] --- server  

With UDP traffic ACK on (another ACK can be added from client before the server sending the reply):

client --- [message] --> server  
client <-- [ACK] --- server  
client <-- [reply]--- server 

#### Protocol details
See the header file  


### In debug mode:

Session ID and Transition ID are hard coded as 654321 and 100000 respectively.
 

Server
```console
$ ./server -T 8888 -d 
listen on socket: 3, port: 8888

[Debug mode]
Read A0 ......
Send A1 --- AUTH1:123456
Read A2 ......
Send A3 --- Status:0, SID:654321
Close TCP connection ...
Start UDP query process ...
Receive UDP query: SID:654321, TID:100000, URL:www.google.com
Send UDP Reply packet --- SID:654321, TID:100001, Timestamp:1523221001, Status:0
```
Client
```console
$ ./client -N 192.168.1.109 -T 8888 -U aaa -P bb11cc -q www.google.com -d
Debug mode SID:654321
Debug mode TID:100000
Receive UDP --- TID:100001, Timestamp: 1523221001, Status:OK, Status Value: 0x0
```

### In normal mode:

Server
```console
$ ./server -T 8888 -n
listen on socket: 3, port: 8888

[Normal mode]
Read A0 ......
Send A1 --- AUTH1:754110595
Read A2 ......
Send A3 --- Status:0, SID:868185947
Close TCP connection ...
Start UDP query process ...
Receive UDP query: SID:868185947, TID:1804289383, URL:www.google.com
Send UDP Reply packet --- SID:868185947, TID:1804289384, Timestamp:1523221429, Status:0
```
Client
```console
$ ./client -N 192.168.1.109 -T 8888 -U aaa -P bb11cc -q www.google.com -n
Receive UDP --- TID:1804289384, Timestamp: 1523221429, Status:OK, Status Value: 0x0
```
### In normal mode with UDP traffic ACK on:

Server
```console
$ ./server -T 8888 -n -t
listen on socket: 3, port: 8888

[Normal mode]
Read A0 ......
Send A1 --- AUTH1:1754617572
Read A2 ......
Send A3 --- Status:0, SID:2021708448
Close TCP connection ...
Start UDP query process ...
Receive UDP query: SID:2021708448, TID:1804289383, URL:www.google.com
Send UDP-traffic verifying ACK package
Send UDP Reply packet --- SID:2021708448, TID:1804289384, Timestamp:1523221348, Status:0
```
Client
```console
$ ./client -N 192.168.1.109 -T 8888 -U aaa -P bb11cc -q www.google.com -n -t
Wait for UDP-traffic verifying ACK ....
Receive UDP --- TID:1804289384, Timestamp: 1523221348, Status:OK, Status Value: 0x0
```