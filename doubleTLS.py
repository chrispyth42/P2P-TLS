#!/usr/bin/python3.6

#################################################################################################################################################################
#References
#   Generating self-signed certificate     https://cryptography.io/en/latest/x509/tutorial/
#   RSA Cryptography                       https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
#   TLS/SSL secured socket                 https://docs.python.org/3/library/ssl.html
#   Multithreading                         https://realpython.com/intro-to-python-threading/
#
#################################################################################################################################################################
#Description
#   This function is intended to create a secure peer to peer connection between two remote hosts. It accomplishes this
#   by having both peers act as both a client and server at the same time. Each having their own self-signed certificate and password authentication 
#   so that neither host can easily abuse the other
#   
#   It's worth noting that I'm not a cryptography, or data-in-transit security expert. I'm fairly certain that I've implemented
#   everything correctly, but be sure to scrutinize my code for security flaws before using this for any practical application.
#   I'm not liable if you get your secrets stolen. this project was done as a fun thing in response to  the "Earn IT" act which
#   has noble goals on the surface, but aggressively targets privacy and end to end encryption in practice https://www.eff.org/document/earn-it-act
#  
#   The idea is that if I can spin this up in my free time over the span of a couple weeks, then what's to stop a team of 2-3 experts from building out
#   a peer to peer encrypted connection system in a weekend? It really makes the idea of trying to legislate encryption seem silly imo
# 
#   This has only really been tested in a LAN environment, and I'm not yet sure how it behaves over the internet
#
#################################################################################################################################################################

#Items necessary to perform operations with private/public keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

#Self-signed certificate creation
from cryptography import x509
from cryptography.x509.oid import NameOID

#Symmetric key generation
import cryptography.fernet
from cryptography.fernet import Fernet

#Python server/client module, as well as ssl module to wrap the socket in TLS
import socket
import ssl

#Detecting whether the script is running in Windows or otherwise by importing the msvcrt module
try:
    import msvcrt
    win=1
except:
    win=0

#Multithreading for simultaneously sending and recieving messages
import threading

#GUI inports
import tkinter as tk    #Standard python GUI library
import re               #For user input validations

#For managing the self-signed cert, and incoming public certificates
import os
import sys

#For creating a random alias for the certificate
import random
import datetime
import getpass

#Master function that encompasses the entire process
def connect(args=dict()):

    #Globals used to recieve return values from different threads
    r_key = list()      #used to store the remote public key recieved in passExchangeClient()
    c_socket = list()   #used to pass the client socket object between the establishConnection function, and the main serverclient function 
    p_auth = list()     #used to confirm client password authentication

    #Hashing algorithm to use in key generation
    hashingAlgorithm = hashes.SHA512()
    passwd_hashingAlgorithm = hashes.SHA256()
    passwd_attempts = 4
    BufferSize = 1024


    ####################################################################################################################################
    # Key and Certificate generation and usage functions
    ####################################################################################################################################

    #Generate key pair
    def makeKey():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return {'private':private_key,'public':public_key}


    #Encrypt a message with assymetric public key
    def encrypt(pub,message):
        encrypted = pub.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashingAlgorithm),
                algorithm=hashingAlgorithm,
                label=None
            )
        )
        return encrypted

    #Decrypt a message with assymetric private key
    def decrypt(priv,message):
        decrypted = priv.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashingAlgorithm),
                algorithm=hashingAlgorithm,
                label=None
            )
        )
        return decrypted

    #Encoding public key as bytestring
    def pubString(pub):
        pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem
    #Unpacking a bytestring public key into a key object
    def readPub(pubString):
        public_key = serialization.load_pem_public_key(
            pubString,
            backend=default_backend()
        )
        return public_key

    #Writing encrypted private key to file (for use with the certificate)
    def writeKey(priv,passwd):
        priv = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passwd)
        )
        with open('Identity/private_key.pem', 'wb') as f:
            f.write(priv)

    #Generating a self-signed certificate with an existing private key
    def makeCert():
        if not os.path.isfile('Identity/certificate.pem'):
            #Generate private key
            key = makeKey()['private']
            
            #Get password input from user for private key
            password = ''
            while True:
                if not args:
                    passInp = passwordPrompt()
                else:
                    passInp = passwordPromptNG()

                if passInp is None:
                    exit()
                if not passInp == b'':
                    password = passInp
                    break
            
            #Generate ranom alias
            aliasID = f"{random.randint(1,10000000)}".zfill(8)
            alias = f"Anon{aliasID}"

            #The only data we're adding on are an organization name, and the computer's hostname
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, alias)])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                #Valid for one year
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u'localhost')]),
                critical=False,
            # Sign the certificate with the private key
            ).sign(key, hashes.SHA256(), default_backend())

            #Write certificate to file        
            with open('Identity/certificate.pem','wb') as fp:
                fp.write(cert.public_bytes(serialization.Encoding.PEM))

            #Write private key to file
            writeKey(key,password)

    ####################################################################################################################################
    # Secure connection and Authentication functions    
    ####################################################################################################################################

    #serverSocket: Used to listen for the initial inbound connection, and facilitates TLS over the entire transaction
    #remoteSocket: Facilitates the connection to the remote socket that's been connected to
    #c_socket[0] : Acts as a client socket to the remote server that's been connected to
    def clientServer(keypasswd,hostpassword,remoteaddress,remotepassword,Port,timeout):
        #Host socket object
        servercontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        servercontext.load_cert_chain('Identity/certificate.pem', 'Identity/private_key.pem',password=keypasswd)

        serverSocketI = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        serverSocket = servercontext.wrap_socket(serverSocketI, server_side=True)

        #Bind the server socket to localhost, and turn off timeout so it can listen forever
        try:
            serverSocket.bind(('0.0.0.0',Port))
        except OSError:
            print("S: Likely port already in use (Linux has a brief timeout between runs)")
            return
        serverSocket.settimeout(None)

        #The socket accept operation has doesn't seem to have a means of exiting once it's started. So I worked around this by
        #having this function running in a separate thread, which makes a connection to localhost 
        def exitCatchTM(Port):
            #Hold here until timeout criteria is reached, then close the connection
            x = datetime.datetime.utcnow().timestamp()
            while (not ((datetime.datetime.utcnow().timestamp() - x) > timeout)) or not timeout:
                pass

            if not c_socket:
                dummysocket = socket.create_connection(('127.0.0.1',Port))
                clientContext = ssl.SSLContext(ssl.PROTOCOL_TLS)
                dummySocketS = clientContext.wrap_socket(dummysocket, server_hostname='127.0.0.1')
        
        def exitCatchKP(Port):
            input()
            if not c_socket:
                dummysocket = socket.create_connection(('127.0.0.1',Port))
                clientContext = ssl.SSLContext(ssl.PROTOCOL_TLS)
                dummySocketS = clientContext.wrap_socket(dummysocket, server_hostname='127.0.0.1')

        #Activate client socket function, as well as a function that connects to localhost to fulfill the exit condition
        listener = threading.Thread(target=establishConnection,args=(remoteaddress,Port), daemon=True)
        listener.start()

        quitK = threading.Thread(target=exitCatchKP,args=(Port,), daemon=True)
        quitK.start()
        quitT = threading.Thread(target=exitCatchTM,args=(Port,), daemon=True)
        quitT.start()

        print(f"S: Listening on port {Port} (Press Enter to exit)...")

        #Start listening for connection
        serverSocket.listen(1)
        try:
            remoteSocket, address = serverSocket.accept()
        except ConnectionAbortedError:
            print("S: Connection Cancelled, or timed out")
            return 
        
        #If the remote connection was localhost (operation cancelled), exit the script
        if address[0] == '127.0.0.1':
            remoteSocket.close()
            print("S: Connection Cancelled, or timed out")
            return
        if address[0] != remoteaddress:
            remoteSocket.close()
            print(f"S: Connection recieved from unexpected host ({address[0]})")
            return

        #Wait for the establish function to exit before continuing, then make sure it worked
        listener.join()

        #Exit if nothing was returned
        if not c_socket:
            return

        print(f"S: Established connection from {address[0]}")

        
        #Generate keypair for password exchange
        key = makeKey()
        print("S: Generated Keypair")

        #Hash the passwords before sending them over the wire
        h = hashes.Hash(passwd_hashingAlgorithm,backend=default_backend())
        h.update(bytes(hostpassword,'utf8'))
        hostpassword = h.finalize()
        h = hashes.Hash(passwd_hashingAlgorithm,backend=default_backend())
        h.update(bytes(remotepassword,'utf8'))
        remotepassword = h.finalize()

        #Activate password client function
        passwordClient = threading.Thread(target=passExchangeClient,args=(remotepassword,), daemon=True)
        passwordClient.start()

        #Send the other node the public key, then wait for password attempt
        remoteSocket.send(pubString(key['public']))
        print(f"S: Sent public key to {address[0]}")

        #If the password matches, send a Granted message. Else send denied
        attempts = 0
        while attempts < passwd_attempts:
            
            passAttempt = remoteSocket.recv(BufferSize)
            #This block is in a try-except, in the event that the other person exits on password retry
            try:
                #If password match, send Granted response and break loop
                if decrypt(key['private'],passAttempt) == hostpassword:
                    remoteSocket.send(bytes("Granted",'utf8'))
                    print(f"S: Password match from {address[0]}")
                    break
                else:
                    remoteSocket.send(bytes("Denied",'utf8'))
                    print(f"S: Password failed attempt from {address[0]}")
                    attempts += 1
            except:
                print(f"S: {address[0]} Left during password authentication")
                return

        if attempts == passwd_attempts:
            print("S: Password attempts exceeded.")
            return

        #Wait for the client to process the response before continuing
        passwordClient.join()

        #Exit if client authentication failed
        if not p_auth:
            return

        #Symmetric Key Exchange
        #Generate and send it out via the remote public key
        symmkeyLocal = Fernet.generate_key()
        c_socket[0].send(encrypt(r_key[0],symmkeyLocal))
        symmkeyLocal = Fernet(symmkeyLocal)
        print(f"C: Sent symmetric key to {address[0]}")

        #Recieve and decode it with local private key
        symmkeyRemote = remoteSocket.recv(BufferSize)
        symmkeyRemote = decrypt(key['private'],symmkeyRemote)
        symmkeyRemote = Fernet(symmkeyRemote)
        print(f"S: Recieved symmetric key from {address[0]}")

        #With all that information, finally initialize the Chat function
        return {
            'localS':remoteSocket,
            'remoteS':c_socket[0],
            'localK':symmkeyLocal,
            'remoteK':symmkeyRemote
        }

    #Function that runs in a separate thread, and connects to a remote server while main simultaneously listens for its own remote connection 
    def establishConnection(clientaddress,Port):
        #TLS Client context
        clientContext = ssl.SSLContext(ssl.PROTOCOL_TLS)
        #Attempt to connect to a remote address with a regular socket
        print(f"C: Attempting connection to {clientaddress} port {Port}...")
        
        #Ignore timeout errors and continually attempt to connect until it succeeds
        while True:
            try:
                clientSocketI = socket.create_connection((clientaddress, Port))
                break
            except TimeoutError:
                pass
            except ConnectionAbortedError:
                print('C: A connection was established, but then refused by the host')
            except OSError:
                print('C: No route found found to host')

        #After connection, secure the socket
        clientSocket = clientContext.wrap_socket(clientSocketI, server_hostname=clientaddress)
        #Pass that socket up to the global scope pefore the therad ends, so that the main function can utilize it
        print(f"C: Connection established to {clientaddress}")

        #Get remote address and certificate to validate if a cert is good or not
        raddr = clientSocket.getpeername()[0]
        rcert = clientSocket.getpeercert(True)

        #Clean the remote address to use as a filename when storing remote public cert to disk
        raddr = re.sub(r'[^a-zA-Z0-9\.]','',raddr)
        #If there isn't currently a cert stored for the address, write to disk
        if not os.path.isfile(f'RemoteCerts/{raddr}'):
            fp = open(f'RemoteCerts/{raddr}','wb')
            fp.write(bytearray(b for b in rcert))
            fp.close()
            print(f"C: {raddr} added to known hosts")
        
        #If it does exist, read its contents and compare it to the just retrieved one
        else:
            fp = open(f'RemoteCerts/{raddr}','rb')
            storedCert = b''
            for c in fp:
                storedCert += c
            fp.close()

            if storedCert == rcert:
                print(f'C: {raddr} identity is the same')
            else:
                print(f'C: ALERT - {raddr} identity has changed\t <-------------------')

        #Send the socket up to the main thread, and disable timeout
        c_socket.append(clientSocket)
        c_socket[0].settimeout(None)

        return

    #Facilitates the client side of the password exchange
    def passExchangeClient(remotepassword):
        #Recieve public key, then send back an encrypted password attempt with it
        pubkey = c_socket[0].recv(BufferSize)
        pubkey = readPub(pubkey)
        print("C: Recieved public key from remote host")
        r_key.append(pubkey)

        attempts = 0
        while attempts < passwd_attempts:
            #Send password attempt
            c_socket[0].send(encrypt(pubkey,remotepassword))
            print("C: Sent password attempt")

            #Then wait for a response and act on it
            response = c_socket[0].recv(BufferSize)
            if response == b'Granted':
                print("C: Password accepted by remote host")
                p_auth.append(1)
                break
            else:
                print("C: Password rejected by remote host")
                attempts += 1
                if attempts < passwd_attempts:
                    #Provide a tkinter input if running gui, or exit the program on wrong attempt
                    if not args:
                        remotepassword = passwordWindow()
                        if not remotepassword:
                            c_socket[0].close()
                            return
                    else:
                        c_socket[0].close()
                        return
                    if remotepassword == None:
                        return
            
    ####################################################################################################################################
    # Input functions
    ####################################################################################################################################
    #Password retry prompt, no GUI edition (Unused because handling keyboard interrupt with multiple threads is terrible lol)
    def passwordWindowNG():
        while True:
            print('-'*20)
            passwd = input("Please enter another password (blank to exit): ").strip()
            if len(passwd) > 0:
                h = hashes.Hash(passwd_hashingAlgorithm,backend=default_backend())
                h.update(bytes(passwd,'utf8'))
                passwd = h.finalize()
                return passwd
            else:
                c_socket[0].close()
                exit()

    #Certificate password entry, no GUI edition
    def passwordPromptNG():
        while True:
            print("A: Certificate has not yet been generated. Please enter a secure password to use as the unlock key:")
            while True:
                p1 = getpass.getpass("A: Password: ").strip()
                p2 = getpass.getpass("A: Confirm: ").strip()
                if (p1 == p2) and (len(p1) > 0):
                    return bytes(p1,'utf8')
                else:
                    print("A: Passwords don't match. Please try again")

    #Password prompt for handling incorrect password attempts as they come in
    def passwordPrompt():
        root = tk.Tk()
        root.resizable(False,False)
        passwd = list()

        def confirmPassword(e=0):
            if p1.get().strip() == p2.get().strip():
                passwd.append(bytes(p1.get().strip(),'utf8'))
                root.destroy()

        def exitOperation():
            passwd.append(None)
            root.destroy()

        #Define window dimentions
        if win:
            w = 220
            h = 155
        else:
            w = 260
            h = 190
        root.geometry(f"{w}x{h}+{round((root.winfo_screenwidth()/2)-(w/2))}+{round((root.winfo_screenheight()/2)-(h/2))}")
        root.title('Crypto-chat startup')

        #Labels
        pL1 = tk.Label(root,text="Password:",width=11)
        pL2 = tk.Label(root,text="Confirm :",width=11)
        description = tk.Label(root,width=28,wraplength=180,text=f"Please enter a password to use for your certificate's private key (Used to keep people from stealing your self-signed cert)\n{'-'*20}")

        #Inputs
        p1 = tk.Entry(root,width=20,show='*')
        p2 = tk.Entry(root,width=20,show="*")

        #Button
        ok = tk.Button(root,text="OK",width=16,command=confirmPassword)
        cancel = tk.Button(root,text="Cancel",width=8,command=exitOperation)

        #Position of everything
        description.grid(row=0,column=0,columnspan=2)
        pL1.grid(row=1,column=0)
        pL2.grid(row=2,column=0)
        p1.grid(row=1,column=1)
        p2.grid(row=2,column=1)
        ok.grid(row=3,column=1)
        cancel.grid(row=3,column=0)

        #Binding for enter button
        root.bind('<Return>',confirmPassword)

        root.mainloop()
        
        #If no input, or cancelled, reutrn none
        if not passwd:
            return None
        elif passwd[0] is None:
            return None
        else:
            return passwd[0]

    def landingWindow(defaults=False):
        #Setting up the window
        startupFrame = tk.Tk()
        startupFrame.resizable(False,False)

        #Define window dimentions
        if win:
            w = 270
            h = 140
        else:
            w = 350
            h = 150
        startupFrame.geometry(f"{w}x{h}+{round((startupFrame.winfo_screenwidth()/2)-(w/2))}+{round((startupFrame.winfo_screenheight()/2)-(h/2))}")
        startupFrame.title('Crypto-chat startup')

        #Break function for the connect button
        returnVar = list()

        #This function is called by both the button, and a keyboard event: pressing return while on password (which sends a parameter by default)
        #So it has a dummy parameter with a default value to cover both situations.
        def chatConnect(e=0):
            #Get variables from the window
            server = serveraddr.get().strip()
            port = portinput.get().strip()
            lPassword = lPasswordField.get().strip()
            rPassword = rPasswordField.get().strip()
            kPassword = kPasswordField.get().strip()

            #Package them into a dictionary, and append them to the return list before closing the window
            returnVar.append({'remoteaddress':server,'Port':port,'hostpassword':lPassword,'remotepassword':rPassword,'keypasswd':kPassword})
            startupFrame.destroy()

        def tab(event):
            event.widget.tk_focusNext().focus()
            return("break")

        
        #Input fields
        serveraddr = tk.Entry(startupFrame,width=27)
        portinput = tk.Entry(startupFrame,width=27)
        lPasswordField = tk.Entry(startupFrame,width=27,show='*')
        rPasswordField = tk.Entry(startupFrame,width=27,show='*')
        kPasswordField = tk.Entry(startupFrame,width=27,show='*')

        #Keep text from previous entry if provided
        if defaults:
            serveraddr.insert(tk.END,defaults['remoteaddress'])
            portinput.insert(tk.END,defaults['Port'])
            lPasswordField.insert(tk.END,defaults['hostpassword'])
            rPasswordField.insert(tk.END,defaults['remotepassword'])
            kPasswordField.insert(tk.END,defaults['keypasswd'])


        #Tab behavior
        serveraddr.bind('<Tab>',tab)
        portinput.bind('<Tab>',tab)
        lPasswordField.bind('<Tab>',tab)
        rPasswordField.bind('<Tab>',tab)
        kPasswordField.bind('<Tab>',tab)

        #Enter behavior
        startupFrame.bind('<Return>',chatConnect)

        #Connect button
        connectBtn = tk.Button(startupFrame,text="Connect",width=20,command=chatConnect)
        
        #Labels
        serverLabel = tk.Label(startupFrame,text="Remote Address:")
        portLabel = tk.Label(startupFrame,text="Port: ")
        lPasswordLabel = tk.Label(startupFrame,text="Local Password:")
        rPasswordLabel = tk.Label(startupFrame,text="Remote Password:")
        kPasswordLabel = tk.Label(startupFrame,text="Key Password:")

        #Positions of everything
        serverLabel.grid(row=2,column=0)
        serveraddr.grid(row=2,column=1)
        portLabel.grid(row=3,column=0)
        portinput.grid(row=3,column=1)
        lPasswordLabel.grid(row=4,column=0)
        lPasswordField.grid(row=4,column=1)
        rPasswordLabel.grid(row=5,column=0)
        rPasswordField.grid(row=5,column=1)
        kPasswordLabel.grid(row=6,column=0)
        kPasswordField.grid(row=6,column=1)
        connectBtn.grid(row=7,column=0,columnspan=3)

        #Run the window
        startupFrame.mainloop()

        #If the OK button was used to exit, return the input
        if returnVar:
            return returnVar[0]
        else:
            return None

    #Window to get a new password from the user if a wrong one was input
    def passwordWindow():
        #Window parameters
        root = tk.Tk()
        w = 370
        h = 80
        root.geometry(f"{w}x{h}+{round((root.winfo_screenwidth()/2)-(w/2))}+{round((root.winfo_screenheight()/2)-(h/2))}")
        root.title('Wrong password')

        #Return variable
        output = list()

        #Function to run on OK or enter press that exits the function if the password field is populated
        def passSubmit(e=0):
            if pField.get().strip():
                output.append(pField.get().strip())
                root.destroy()

        #Window objects and their positions
        pField = tk.Entry(root,show="*",width=30)
        description = tk.Label(root,text="Password to server was incorrect. Please enter another")
        okbutton = tk.Button(root,text="OK",width=15,command=passSubmit)
        description.grid(row=0,column=0)
        pField.grid(row=1,column=0)
        okbutton.grid(row=2,column=0)

        #Binding the return key to the passSubmit function, and then starting the window
        root.bind('<Return>',passSubmit)
        root.mainloop()
        
        #If the user exit the function early, return none. Else returned the hash representation of the password
        if not output:
            return None
        else:
            h = hashes.Hash(passwd_hashingAlgorithm,backend=default_backend())
            h.update(bytes(output[0],'utf8'))
            output[0] = h.finalize()
            return output[0]

    ####################################################################################################################################
    # Main Loop    
    ####################################################################################################################################
    def main(previousOpts=False):
        #Reset globals on re-call
        c_socket.clear()
        r_key.clear() 
        p_auth.clear()

        #Create directories to house the host identity, and remote public certs
        if not os.path.isdir('Identity'):
            os.mkdir('Identity')
        if not os.path.isdir('RemoteCerts'):
            os.mkdir('RemoteCerts')       
            
        #Generate self-signed certificate if it doesn't exist
        makeCert()

        #Run the prompt, and exit if they exited that window
        opts = landingWindow(previousOpts)
        if not opts:
            return
        
        #Loop to ensure good inputs
        inputCheck = True
        while inputCheck:
            #Exit if they quit the options window
            if not opts:
                return

            #Check that the port number is above 1000, and that all other inputs have something there before proceeding
            if not re.match(r'[0-9]?[1-9][0-9]{3}',opts['Port']):
                print("A: Port number must be an integer value >= 1000")
                opts = landingWindow(opts)
            elif opts['keypasswd'] == '':
                print("A: Please provide the password to your server key")
                opts = landingWindow(opts)
            elif opts['hostpassword'] == '':
                print("A: Please provide the password to set for your side of the connection")
                opts = landingWindow(opts)
            elif opts['remotepassword'] == '':
                print("A: Please provide a password to the other person's connection")
                opts = landingWindow(opts)
            elif opts['remoteaddress'] == '':
                print("A: Please provide the address of the machine to connect to")
                opts = landingWindow(opts)
            else:
                #Create a context that doesn't go anywhere, just for making sure the key password is correct before proceeding
                try:
                    dummycontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    dummycontext.load_cert_chain('Identity/certificate.pem', 'Identity/private_key.pem',password=opts['keypasswd'])
                    inputCheck=False
                except:
                    print("S: Server certificate password was incorrect.")
                    opts = landingWindow(opts)

        opts['Port'] = int(opts['Port'])
        return clientServer(opts['keypasswd'],opts['hostpassword'],opts['remoteaddress'],opts['remotepassword'],opts['Port'],timeout=0)

    def mainNG(args):        
        
        #Create directories to house the host identity, and remote public certs
        if not os.path.isdir('Identity'):
            os.mkdir('Identity')
        if not os.path.isdir('RemoteCerts'):
            os.mkdir('RemoteCerts')
        #Generate self-signed certificate if it doesn't exist
        makeCert()

        #Check that the port number is above 1000, and that all other inputs have something there before proceeding
        if not type(args['port']) == int:
            raise Exception("Port number must be an integer value >= 1000")
        elif args['port'] < 1000:
            raise Exception("Port number must be an integer value >= 1000")
        elif args['keypassword'] == '':
            raise Exception("No certificate key password provided")
        elif args['hostpassword'] == '':
            raise Exception("No server-side password value provided")
        elif args['remotepassword'] == '':
            raise Exception("No password attempt provided")
        elif args['remoteaddress'] == '':
            raise Exception("No remote address provided")
        elif not type(args['timeout']) == int:
            raise Exception("Timeout variable must be an integer value")
        elif args['timeout'] < 0:
            raise Exception("Timeout must be a positive value (0 for no timeout)")
        else:
            #Create a context that doesn't go anywhere, just for making sure the key password is correct before proceeding
            try:
                dummycontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                dummycontext.load_cert_chain('Identity/certificate.pem', 'Identity/private_key.pem',password=args['keypassword'])
            except:
                raise Exception("Incorrect cerificate password provided")

        return clientServer(args['keypassword'],args['hostpassword'],args['remoteaddress'],args['remotepassword'],args['port'],args['timeout'])

    #Run the main function, and return the live sockets to whatever script called it
    if not args:
        return main()
    else:
        return mainNG(args)
