# P2P-TLS

A learning experiment project in which I created a TLS connection between two hosts using self-signed certificates, and used keypair exchanges underneath that to facilitate additional password authentication. I can't really vouch for its security in practice, but it helped me learn how to code a bunch of cool things including self-signed certificate generation, multithreading, and keypair generation

## doubleTLS.py

Contains an importable function which handles certificate creation, password authentication, and socket creation needed to facilitate a peer to peer encrypted connection. It accomplishes it by running a server side socket, and client side socket in parallel, so that both nodes of the connection are acting as a client/server simultaneously. The intention is that having both nodes in the system be a server would eliminate the possibility of abuse that comes with just 1 node being a server

References used, and a description of the project can be found at the top of the script. Furthermore, a chart illustrating the process of what it's doing can be found in 'flow.png'

This function requires that the 'cryptography' module be installed, running in python 3.6 or later. If any flaws are found in its design, feel free to let me know! I'd be more than happy to improve it

## test.py

Contains the most basic implementation of doubleTLS.py. It describes the inputs and outputs of the function, and how to use the sockets/keys it returns to communicate between two hosts

## chat.py

Contains a basic chatroom application built atop doubleTLS.py! Allowing a conversation to take place over the generated connection


