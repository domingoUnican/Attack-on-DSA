import time
from Queue import Queue
#import multiprocessing
def CVP(B,t):
    '''
    Method that, on input B LLL-reduced, return a vector u such that
    the norm of u-t is small
    '''
    n=B.nrows()
    b=t
    G,M=B.gram_schmidt()
    for j in range(n,0,-1):
        c=((b*G[j-1])/(G[j-1]*G[j-1])).round()
        b=b-c*B[j-1]
    return t-b

def parameters_attack(m, r, s, t, delta, q):
    n = len(r)
    alpha = [0] + [mod(2^(-t)*(m[i]/s[i]-m[0]/s[0]),q) for i in range(1,n)]
    beta =  [1] + [mod(2^(-t)*(-r[i]/s[i]+r[0]/s[0]),q) for i in range(1,n)]
    L = matrix.diagonal([1]+[q for i in range(1,n)])
    L[0]=beta
    L = matrix(ZZ,n,L.rows(),sparse=False)
    for i in range(0,n):
        for j in range(1,n):
            L[i,j] *= 2^(delta)
    L = L.LLL()
    return L,2^(delta)*vector(ZZ,alpha)


"This code is studied in https://github.com/guanzhi/CryptoWithSageMath"
import hashlib

def digest(msg):
    msg = str(msg)
    return Integer('0x' + hashlib.sha1(msg).hexdigest())

def DSA_signature(m,p,q,g,a, size, t, k=1):
    r,s =0, 0
    while not s:
        k0 = k
        while not r or not k0:
            k0 = k + 2^(t)*ZZ.random_element(0,2^size)
            k0 = mod(k0,q)
            r = mod(mod(g,p)^a,q)
        e = digest(m)
        e = mod(e,q)
        s = mod((e+a*r)/k0,q)
    return e,r,s
# Parameters from openssl.
q = ZZ("00ab4496500577552112bf282ebd8c0f6f8830033f",16)
p = ZZ("00eb7009da25d0137954f837400a0b976bc4cb363b7449fd5c66184be225\
        a9dfa655189a5b8403a6dcde225c6c\
        4fb3f80d6b0a4e4065ef07d3ddec83\
        0d38aaa3c83e655445eda485d1680b\
        44dcc34d2c8da2de08842173fbe1c3\
        ca0de22b726ce6c8f757ba00a5332b\
        841b4abd94e1419f0901bfa767e1e6\
        c69ce0338d50bcde11",16)
g = ZZ("1425078a7ffdedbb74ef1601126d99\
        b78c0d788959223e6649c870a5326c\
        292927282218aec50ff8026dc7845c\
        c23e4e89247bc745658b4fc6ceca44\
        402a95da97c994c7c86c7c151c6123\
        bc3874f6bf98dd2d1d71ba24377115\
        735d59a3e055119db678e98261a012\
        6a2a08bc958a68f8fdfa6ffa9e3219\
        a5d1c105ea5340bd",16)

def minimun(p,q,g,error,out, t=0):
    k = ZZ.random_element(0,q-1)
    a = ZZ.random_element(1,q-1)
    # Now, we generate messages with their signatures:
    m = []
    r = []
    s = []
    #We take the size of the non equal part to be the total number of bits minus the error
    size = len(q.bits())-error
    for i in range(3):
        m_str = "Your secret pin is:%s"%(ZZ.random_element(0,2^100))
        e0,r0,s0 = DSA_signature(m_str,p,q,g,a,error,t,k)
        m.append(e0)
        r.append(r0)
        s.append(s0)
    L, u = parameters_attack(m,r,s,t,size,q)
    result = mod(CVP(L,u)[0],q)
    total = 3
    while result != a and total < 100:
        m_str = "Your secret pin is:%s"%(ZZ.random_element(0,2^100))
        e0,r0,s0 = DSA_signature(m_str,p,q,g,a,size,t,k)
        m.append(e0)
        r.append(r0)
        s.append(s0)
        total += 1
        L, u = parameters_attack(m,r,s,t,size,q)
        result = mod(CVP(L,u)[0],q)
    out.append(total)

tiempo = time.time()
procs = []
for num_bits in range(130,158,3):
    out = []
    for i in range(10):
        minimun(p,q,g,num_bits, out)
    procs.append((num_bits,out))

print procs
print (time.time()-tiempo)
#print list(out)
#minimun(p,q,g,155, out)
