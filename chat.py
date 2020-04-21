#!/usr/bin/python3.6
import doubleTLS

import tkinter as tk    #Standard python GUI library
import datetime         #Datetime for chat output
import textwrap         #Neatly splitting up strings when displaying in chat window
import re               #User input validation
import threading        #To simultaneously send information with c['localS'], and recieve information with c['remoteS']  

r_text = list()     #used to share incoming messages between the chat listener thread, and the tkinter main loop for the chat (tkinter isn't very compatible with multithreading)
BufferSize = 1024

####################################################################################################################################
# Chat Functions
####################################################################################################################################

#Accepts the remote socket, symmetric key, and chat prompt message, and opens a chat conversation
def chat(sendSocket,recieveSocket,symmkeyLocal,symmkeyRemote):
    #Create window
    root = tk.Tk()
    root.resizable(False,False)

    def sendMessage(event):
        #Message from dialog box
        msg = textIn.get("1.0",tk.END).strip()

        #Send message to remote host
        sendSocket.send(symmkeyRemote.encrypt(bytes(msg,'utf-8')))

        #Slice the message into 48 character lines, then append each to the console
        msg = textwrap.wrap(msg,48)
        console.config(state='normal')
        is1 = True
        for line in msg:
            if is1:
                console.insert('end',f"You  {getNow()}" + line + '\n')
            else:
                console.insert('end',' '*14 + line + '\n')
            is1 = False
        console.config(state='disabled')
        console.see('end')  #Scroll to bottom automatically

        #Erase the contents of the input box
        textIn.delete("1.0",tk.END)

    def getMessage(msg):
        #Slice the message into 48 character lines, then append each to the console
        msg = textwrap.wrap(msg,48)
    
        console.config(state='normal')
        is1 = True
        for line in msg:
            if is1:
                console.insert('end',f"Them {getNow()}" + line + '\n')
            else:
                console.insert('end',' '*14 + line + '\n')
            is1 = False
        console.config(state='disabled')
        console.see('end')

    def leave():
        root.destroy()


    #Define its width and height, and position in the center of the screen
    if doubleTLS.win:
        w=499
        h=360
    else:
        w=505
        h=385
    
    root.geometry(f"{w}x{h}+{round((root.winfo_screenwidth()/2)-(w/2))}+{round((root.winfo_screenheight()/2)-(h/2))}")
    root.title("Crypto-Chat")

    #Window elements
    console = tk.Text(root,height=20,width=62,wrap=tk.WORD,yscrollcommand=True,background="#09295c",foreground="white",state='disabled')
    buttonFrame = tk.Frame(root)
    label = tk.Label(buttonFrame,text="Chat:")
    textIn = tk.Text(buttonFrame,height=1,width=40)
    sendBind = textIn.bind('<Return>',sendMessage)
    if doubleTLS.win:
        postBtn = tk.Button(buttonFrame,text="Send",width=10, command= lambda :sendMessage('<Return>'))
        exitBtn = tk.Button(buttonFrame,text="Exit",width=6,command=leave)
    else:
        postBtn = tk.Button(buttonFrame,text="Send",width=7, command= lambda :sendMessage('<Return>'))
        exitBtn = tk.Button(buttonFrame,text="Exit",width=3,command=leave)

    #Positioning window elements
    console.grid(row=0,column=0,sticky=tk.W)
    buttonFrame.grid(row=1,column=0,pady=3)
    label.grid(row=0,column=0,sticky=tk.W)
    textIn.grid(row=0,column=1)
    postBtn.grid(row=0,column=2)
    exitBtn.grid(row=0,column=3)

    #Start listener function for recieved messages
    listener = threading.Thread(target=chatlistener,args=(symmkeyLocal,recieveSocket,), daemon=True)
    listener.start()

    #Main loop
    rLen = len(r_text)
    while True:
        try:
            if rLen < len(r_text):
                rLen = len(r_text)
                getMessage(r_text[-1])

            #Keep main window rolling
            root.update()

            #If listener dies, write disconnect message and disable send button. Also, exit the routine and go to default tkinter mainloop            
            if not listener.is_alive():        
                postBtn.config(state='disabled')
                console.config(state='normal')
                console.insert('end','Chat partner has disconnected.')
                console.config(state='disabled')
                console.see('end')
                textIn.unbind(sendBind)
                break

        #If window is closed, quit without error 
        except tk._tkinter.TclError:
            exit()

    root.mainloop()
    sendSocket.close()
    recieveSocket.close()


#Accepts the remote socket object, and fernet symmetric key, to constantly listen for recieved messages
def chatlistener(symmkeyLocal,recieveSocket):
    try:
        while True:
            #Recieve message from remote host
            message = recieveSocket.recv(BufferSize)
            message = symmkeyLocal.decrypt(message)
            message = message.decode('utf8')

            #Write message to console
            r_text.append(message)

    except ConnectionResetError:
        print("Chat partner has disconnected")
    except:
        pass
        
#Gets the current hour/minute for showing as a timestamp in the console
def getNow():
    now = datetime.datetime.now()
    hm = '('
    if now.hour < 10:
        hm += f'0{now.hour}:'
    else:
        hm += f'{now.hour}:'

    if now.minute < 10:
        hm += f'0{now.minute}): '
    else:
        hm += f'{now.minute}): '

    return hm

def main():
    params = {
        'remoteaddress' :'10.0.0.13',       #127.0.0.1 is used as an exit case in the script. So to connect to localhost, be sure to use your PC's LAN IP address
        'port'          : 5001,             #Port for the script to listen/connect on
        'hostpassword'  : 'P@ssw0rd',       #Password that someone connecting to your device will be required to enter when connecting
        'remotepassword': 'P@ssw0rd',       #Password to submit to the remote host to authenticate the connection
        'keypassword'   : 'G00dP@ssw0rd',   #Password to unlock your certificate's private key (on first run, you'll be prompted for this when it's being created)
        'timeout'       : 5                 #Connection timeout value as an integer value in seconds. (0 to listen forever)
    }

    s = doubleTLS.connect(params)
    if s:
        chat(s['localS'],s['remoteS'],s['localK'],s['remoteK'])

main()
