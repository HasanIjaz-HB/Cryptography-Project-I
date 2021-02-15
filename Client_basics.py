import math
import timeit
import random
import black
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID = 24775

def key_generation(n,P):
     sA = random.randrange(0,n-1)
     QA = sA*P
     return sA,QA
 
def signature_generation(n,m,P,sA):
    k = random.randrange(1, n-2)
    R = k*P
    r = R.x % n
    temp = m + r.to_bytes((r.bit_length() + 7) // 8,byteorder= 'big')
    #print("temp sig is",temp)
    h = SHA3_256.new(temp).hexdigest()
    h = int(h,16)
    h = bin(h)[2:len(bin(n))]
    h = int(h, 2)
    s = (sA * h + k) % n
    return(h,s)
    
    
def signature_verification(m,s,h,QA,P,n):
    V = s*P - h*QA
    v = V.x % n
    temp = m + v.to_bytes((v.bit_length() + 7) // 8,byteorder= 'big')
    print("temp is:",temp)
    h_prime = SHA3_256.new(temp).hexdigest()
    h_prime = int(h_prime,16)
    h_prime = bin(h_prime)[2:len(bin(n))]
    h_prime = int(h_prime, 2)   
    print("h_prime is:",h_prime)
    print("h is",h)
    if (h_prime==h):
        return 1
    else:
        return 0


curve = Curve.get_curve('secp256k1')
n = curve.order
P = curve.generator

#HERE CREATE A LONG TERM KEY
#sA,QA=key_generation(n, P);
sA = 47739507727097583103574014533029612368096643715089728534014772436197620809295
QA = sA*P
lkey=QA
lpkey=sA
print(sA)
print(QA)
m = str(stuID)
m = str.encode(m)
h,s = signature_generation(n, m, P, sA)



#server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, curve)

# HERE GENERATE A EPHEMERAL KEY 
sA,QA=key_generation(n, P);
ekey=QA


try:
   	#REGISTRATION
    mes = {'ID':stuID, 'h': h, 's': s, 'LKEY.X': lkey.x, 'LKEY.Y': lkey.y}
    response = requests.put('{}/{}'.format(API_URL, "RegStep1"), json = mes)		
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())
  
    print("Enter verification code which is sent to you: ")	
    code = int(input())
    mes = {'ID':stuID, 'CODE': code}
    response = requests.put('{}/{}'.format(API_URL, "RegStep3"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())
    #STS PROTOCOL
    
    mes = {'ID': stuID, 'EKEY.X': ekey.x, 'EKEY.Y': ekey.y}
    response = requests.put('{}/{}'.format(API_URL, "STSStep1&2"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    res=response.json()
    print(res)
    QB = res
    	#calculate T,K,U
    temp = QB.values()
    QB = list(temp)
    QB = Point(QB[0] , QB[1], curve)
    
    
    
    
    T = sA*QB
    print(T)
    strg = "BeYourselfNoMatterWhatTheySay"
    print(strg)
    Tx = T.x
    Ty = T.y
    U = str(Tx)+str(Ty)+strg
    #.to_bytes((Tx.bit_length() + 7) // 8,byteorder= 'big')+Ty.to_bytes((Ty.bit_length() + 7) // 8,byteorder= 'big')+strg
    print("U is:",U)
    U = str.encode(U)
    K = SHA3_256.new(U).hexdigest()
    K = int(K,16)
    K = bin(K)[2:len(bin(n))]
    K = int(K, 2)
    K = K.to_bytes((K.bit_length()+7) // 8, byteorder='big')
    print("K is:",K)
    
       
    qbx = str(QB.x)#.to_bytes((QB.x.bit_length() + 7) // 8,byteorder= 'big')
    qby = str(QB.y)#.to_bytes((QB.y.bit_length() + 7) // 8,byteorder= 'big')
    qax = str(QA.x)#.to_bytes((QA.x.bit_length() + 7) // 8,byteorder= 'big')
    qay = str(QA.y)#.to_bytes((QA.y.bit_length() + 7) // 8,byteorder= 'big')
    W1 = qax+qay+qbx+qby
    print("W1 is:",W1)
    W1=str.encode(W1)
    
    #Sign Message
    sigAh,sigAs = signature_generation(n, W1, P, lpkey)

    # Encyption
    cipher = AES.new(K, AES.MODE_CTR)
    ptext = str(str("s")+ str(sigAs)+str("h")+ str(sigAh))
    ptext = str.encode(ptext)
    print("ptext is:",ptext)
    Y1 = cipher.nonce + cipher.encrypt(ptext)
    print("Y1 is:",Y1)
    Y1 = int.from_bytes(Y1, byteorder="big")
    print("int of Y1:",Y1)
    ctext = Y1
    print("ctext before sending",ctext) 
    
    ###Send encrypted-signed keys and retrive server's signed keys
    mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
    response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json = mes)
    if((response.ok) == False): raise Exception(response.json()) 
    ctext= response.json() 
    print("ctext after recieveing:",ctext)
    ctext=ctext.to_bytes((ctext.bit_length() + 7) // 8,byteorder= 'big')
    
   	#Decrypt 
    cipher = AES.new(K, AES.MODE_CTR, nonce=ctext[0:8])
    dtext = cipher.decrypt(ctext[8:])
    print("Decrypted text: ", dtext.decode('UTF-8'))
   
   
   	#verify
    v = signature_verification(dtext, sigAs, sigAh, Qser_long, P, n)
    print("v is:", v)
   
   
   	#get a message from server for 
    #stuID=str(stuID)
    mes = {'ID': stuID}
    response = requests.get('{}/{}'.format(API_URL, "STSStep6"), json=mes)
    ctext= response.json()    
    
    print("w3 is:",ctext)
    ctext=ctext.to_bytes((ctext.bit_length() + 7) // 8,byteorder= 'big')	
    
   	#Decrypt
    cipher = AES.new(K, AES.MODE_CTR, nonce=ctext[0:8])
    dtext = cipher.decrypt(ctext[8:])
    print("Decrypted text: ", dtext.decode('UTF-8'))
    temp = dtext.decode("UTF-8")
   
   	#Add 1 to random to create the new message and encrypt it
    rndnum=int(temp[temp.find(".")+2:])+1
    msg = temp[0:temp.find(".")+1]

    W4 = str(rndnum)
    cipher = AES.new(K, AES.MODE_CTR)
    ptext = msg + " " + W4 
    print("msg is:", ptext)
    ptext=str.encode(ptext)
    temp = cipher.nonce + cipher.encrypt(ptext)
    temp = int.from_bytes(temp, byteorder="big")
    ct = temp
    
    #send the message and get response of the server
    mes = {'ID': stuID, 'ctext': ct}
    response = requests.put('{}/{}'.format(API_URL, "STSStep7&8"), json = mes)
    ctext= response.json()         
    print("response from server:",ctext)
    ctext=ctext.to_bytes((ctext.bit_length() + 7) // 8,byteorder= 'big')
    cipher = AES.new(K, AES.MODE_CTR, nonce=ctext[0:8])
    dtext = cipher.decrypt(ctext[8:])
    print("Decrypted text: ", dtext.decode('UTF-8'))
except Exception as e:
	print(e)