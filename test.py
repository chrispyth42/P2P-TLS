import doubleTLS

#Parameters for accessing it no gui (Throws error on incorrect input)
params = {
    'remoteaddress' :'10.0.0.13',       #127.0.0.1 is used as an exit case in the script. So to connect to localhost, be sure to use your PC's LAN IP address
    'port'          : 5001,             #Port for the script to listen/connect on
    'hostpassword'  : 'p@ssw0rd',       #Password that someone connecting to your device will be required to enter when connecting
    'remotepassword': 'p@ssw0rd',       #Password to submit to the remote host to authenticate the connection
    'keypassword'   : 'G00dP@ssw0rd',   #Password to unlock your certificate's private key (on first run, you'll be prompted for this when it's being created)
    'timeout'       : 0                 #Connection timeout value as an integer value in seconds. (0 to listen forever)
}

c = doubleTLS.connect(params)
#Create the connection using the arguments specified above. If successful, it returns:
# c['localS']   :   TLS wrapped socket connection where the local machine's certificate is being used
# c['localK']   :   Fernet symmetric key generated on the local machine
# c['remoteS']  :   TLS wrapped socket connection where the remote machine's certificate is being used
# c['remoteK']  :   Fernet symmetric key generated on the remote machine 

#Exit early if the connect function didn't return anything
print('-'*40)
if not c:
    print('Connection failed')
    exit()

#Details of objects returned by the connect function
print("Connection Success!")
print(f'Running on port {params["port"]}\n')

print(f'Serving on {c["localS"].getsockname()[0]} to {c["localS"].getpeername()[0]} with {c["localS"].version()}')
print(f'\tServer symmetric key: {c["localK"]._encryption_key}')

print(f'Connected to {c["remoteS"].getpeername()[0]} with {c["remoteS"].version()}')
print(f'\tRemote symmetric key: {c["remoteK"]._encryption_key}\n')


#Sending an encrypted message to the other host
msgOUT = f"Hello from {c['localS'].getsockname()[0]}!"
msgOUT = c['localK'].encrypt(bytes(msgOUT,'utf8'))      #Encrypt it using the server side symmetric key
c['localS'].send(msgOUT)                                #Send it out using the server socket

#Recieve and decrypt a message from the other host
msgIN = c['remoteS'].recv(1024)                         #Recieve the message coming in from the remote socket
msgIN = c['remoteK'].decrypt(msgIN)                     #Decrypt it with the remote symmetric key before printing
print(f"Remote server says:\n\t{msgIN}")                      

