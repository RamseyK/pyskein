from time import time, sleep
from random import randrange
from threading import Thread
from skein import skein512

data = bytes(10**8)

res = []
for THREAD in range(2):
    h1 = skein512()
    h2 = skein512()
    t1 = Thread(target=h1.update, args=(data,))
    t2 = Thread(target=h2.update, args=(data,))

    t = time()
    if THREAD:
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    else:
        h1.update(data)
        h2.update(data)
    res.append(time()-t)
    assert h1.digest() == h2.digest()
print("speed-up:", res[0]/res[1])
