from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import random
def modinv(a, m):
    if a < 0:
        a = a+m
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def KeyGen(E):
    n = E.order               #Prime int
    P = E.generator
    s = random.randint(1,n-2) #choos a secret integer s < n − 1 
    Qa =s*P         
    return s,Qa               #Curve parameters (a, b, p, and P ) and her public key Q are published, s is kept private

def SignGen(m, E, sA):
    hash_val_hex = SHA3_256.new(m).hexdigest() #hash the message
    h = int(hash_val_hex, 16) #??? % q         #convert hexademical value to the decimal value

    n = E.order
    P = E.generator

    k = random.randint(1,n-1) #selects a random integer k such that 0 < k < n.
    R = k*P                   #computes R = k*P = (xr, yr)
    r = R.x % n               #r=xr mod n 
    s = (modinv(k,n) * (h+ sA*r )) % n  #s = ( k^-1 * (h + sA * r ) ) mod n
    return r,s                #signature for m is (r, s)

def SignVer(m, s, r, E, QA):    #Verifying the signature given m and QA and curve parameters
    hash_val_hex = SHA3_256.new(m).hexdigest() #get hash value of message in hexadecimal format
    h = int(hash_val_hex, 16) #??? % q  #convert hexademical value to the decimal value

    n = E.order
    P = E.generator
    u1 = (modinv(s,n)*h) % n    #u1 = s^−1 * h mod n
    u2 = (modinv(s,n)*r) % n    #u2 = s^−1 * r mod n
    V = u1*P + u2*QA            #V = u1*P + u2*QA = (xv,yv)
    v = V.x % n                 #v = xv mod n
    if v == (r % n): return True
    return False