from Crypto.Util.number import GCD, inverse

# d^-1(x) = a^-1 (x - b) % 256

pre = [0x89, 0x50, 0x4e]
post = [0x60, 0x09, 0xeb]

for a in range(256):
    if GCD(a,256)!=1:
        continue
    inv_a = inverse(a, 256)
    for b in range(256):
        q = 1
        for i in range(3):
            if (inv_a * (post[i] - b) ) % 256 != pre[i]:
                q=0
                break
        if(q):
            print(a, b)
            # 15, 89