>>>
POST / HTTP/1.1
User-Agent: test-suite
Content-Type: text/plain
Transfer-Encoding: chunked
Host: example.com

3
qwe
3
asd
0
X-trailer: 42


<<<
HTTP/1.1 200 OK
Server: test-suite
Content-Type: text/plain
Transfer-Encoding: chunked

3
xxx
3
yyy
0
X-trailer: 69

