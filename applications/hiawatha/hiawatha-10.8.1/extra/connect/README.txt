This tool can be used to connect to a SSH daemon via Hiawatha, which has the TunnelSSH option set with an authentication code.

Usage: ssh <username>@localhost -o ServerAliveInterval=15 -o "ProxyCommand=./connect <hostname> <authentication code>"
