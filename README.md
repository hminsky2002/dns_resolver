# DNS Resolver server
This is a dns resolver server that takes in DNS requests 
and resolves them from an authoritative dns server! 
It uses only python module libraries, so can be run with any
python3 distribution with `python server.py <PORT>`. It can be 
teseted via running `client.py`, or with with the dig command,
such as `dig @localhost -p 53 example.com`
