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
q = ZZ("00a70faa57e1923456b9dc196bb03668b9ba133e30be0ac7d3a65f9aca4c831301",16)
p = ZZ("00b872fd7db5fa150d1474c8ff613b\
        c1487ed6a51a54470075de789545ff\
        fd7a72b71d4af97c3c8a5a39c963e5\
        77ef792df28a3d3700d61be03b3e11\
        ccf08c9d4b91b3ed22e0dfc332a5fe\
        ad01622dcc402657cdf1f930a917f6\
        996bff5f02f8f5079511dd8e1b988c\
        9148875caf59dea4e4fa0c601161f0\
        e8ad718afbe690047fe089b325f79d\
        0d909633b99b60137100bb4cdb30bc\
        4d405b1668e9a35e6bf855e6072c26\
        80457b8dbb95036d73f2ca29cf2166\
        ea315d43fb9440e75ef8b9a0c60f11\
        c033c0c441883953d497a2ce07cc94\
        8ee235878006cce9927ba52f8a1c4e\
        df63dfead305d6f8d42d9872ebf2a5\
        a9394dccf305e1f47604e0f2defcb3\
        2154241613cfd8c063c9f0cbca9b9e\
        5badea2804af917f26145399a53236\
        e416d3949996f497312d6afade6491\
        6fd8825f053bbbaacb3bf59a0c3063\
        bec60d10f8945bdf593a19752eac0f\
        9b6b465a5199df54443e7e0531255c\
        b28f75edb3eb234798c73720757b9b\
        7e4eda317e334e1ad780d07e8ca235\
        2ef376897e74bb2014b6511a5a3856\
        50c91c4a2499333f9cea5046afd210\
        89e65715f7fe2d3f4d085c89ae7406\
        b1648f4e1caa4a6918f43b2e417b7f\
        74a491a51af84c3ce350bd52d85318\
        8962d993a80caa88435c5db6f2b2c2\
        fbf025bd221ca497ccd4f23744c821\
        342c5d19c72cbd3dacf718dd6f9822\
        69a31e56fadbed9727afa4225c3d66",16)
g = ZZ("29ba3222538b5a10f30d2408eb7bb4\
        e0e853173d831a8e153d967afd1aa2\
        615e780185be717b3edc302917177d\
        045a1dcc9b02949b0280a6093d9940\
        c5266fae3b6931a8d7c4623612dcf4\
        5f2b011ae6148f87012f5d96809557\
        78720b11d040f30a73b1086905c464\
        6e1bf6791decd4aa24ba689c02a4a9\
        b5d6424f92fe27dd945287dfa462c7\
        d0588c931a72351d2ab81b5b7b4dc2\
        6242cbe65008c9d5ceec85f66056af\
        e303ff11573bc9d8e50b0d982fbccf\
        6f1f987bee76060d4a0f57796c6455\
        f59f8bab8c268cbfb6342010f79fcd\
        48446f1695aa1186d266424edc1447\
        6190f4d311639f869321f03564bfb7\
        79cb336e6a83f0b4f53a68a3bbe59a\
        190a362d8436e0daf0b38a84859806\
        e8c198ae4eabb7998abacc1c49667a\
        190006b8d205cdff8cbc2d9e0e32d0\
        258e266403da9a759449b99d6601f2\
        b48fa3198bf4e0139db9893aa8c04f\
        0a50205b1b34063112bf2c2f0e4a77\
        0d5e972da182cc298681334fb424cc\
        3afa7ac1b43efd4afd8415061ddd38\
        d581e4bd195384faf3dd5b79d87b91\
        ac2c52d8cb92e4955e597f864f01dd\
        0c2365eda56cc2d37e1d76388ceebc\
        6e7502d14301a46e112823140b6150\
        555944418c9dd84f0ed4e8f0e7fb52\
        30364a75b2594d5e4fc2db4a47f94a\
        717a096a8bf098533af5464fffbfcf\
        b4da799f3dd35680e7137fcad69032\
        8b48b7870038c9219130543b195493\
        52d6",16)

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
for num_bits in range(len(q.bits())-40,len(q.bits()-10),2):
    out = []
    for i in range(10):
        minimun(p,q,g,num_bits, out)
    procs.append((num_bits,out))

print procs
print (time.time()-tiempo)
#print list(out)
#minimun(p,q,g,155, out)
