import hashlib
import random
import socket




def H(*a):  # hash func
    a = ':'.join([str(a) for a in a])
    return int(hashlib.sha256(a.encode('ascii')).hexdigest(), 16)


def cryptrand(n=1024):
    return random.SystemRandom().getrandbits(n) % N

# openssl dhparam -text 1024 python

N = '''00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
       4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
       c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
       97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
       c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
       c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
       16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
       9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:
       d0:d4:ca:3c:50:0b:88:5f:e3'''
N = int(''.join(N.split()).replace(':', ''), 16)
g = 2        # gen N
k = 3  # context security

#list of registered users
users = []

def process_register(message, conn):
    I = message[0]
    s = long(message[1])
    v = long(message[2])
    if filter(lambda m:m.get('I') == I, users):
        response = "Username already taken"
        print (response)
        conn.send(response)
    else:
        user = {'I': I, 's': s, 'v': v}
        users.append(user)
        response = "User " + I + " is successfully registered"
        print (response)
        conn.send(response)



def process_authenticate(message, conn):
    I = message[0]
    A = long(message[1])
    
    user = filter(lambda m : m.get('I') == I, users)
    if user:
        print ("Found user " + I)
        s = user[0].get('s')
        v = user[0].get('v')
        b = cryptrand()
        B = (k * v + pow(g, b, N)) % N
        conn.send(str(s))
        conn.send(str(B))


        u = H(A, B)
        S_s = pow(A * pow(v, u, N), b, N)
        K_s = H(S_s)

        # Verify that the keys are equal
        M_c_client = long(conn.recv(1024))
        M_c_server = H(H(N) ^ H(g), H(I), s, A, B, K_s)

        if M_c_client == M_c_server:
            print ("Authentication done and Sessionkey established:")
            print (K_s)
            M_s = H(A, M_c_client, K_s)
            conn.send(str(M_s))
        else:
            print ("Something went wrong in the authentication process:")
            conn.send(str(0))
    else:
        conn.send("Error: Could not find username in database")
        
    
sock = socket.socket()

host = 'localhost'
port = 8080

sock.bind((host, port))
sock.listen(1)
print ("Server is listening for incoming connections...")

while 1:
    conn, addr = sock.accept()
    print ("Incoming request")
    data = conn.recv(1024)

    if not data: break
    msg = data.split(" ")
    header = msg[0]     # header:[register|authenticate]

    if header == "register":
        process_register(msg[1:], conn)
    elif header == "authenticate":
        process_authenticate(msg[1:], conn)
    else:
        print ("Malformed Request")
        
conn.close()



