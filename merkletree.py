import time
import hashlib

def data_hash(array):
      result = []
      for i in array:
            hash = hashlib.md5()
            hash.update(bytes(str(i), encoding='utf-8'))
            result.append(hash.hexdigest())
      return result   

def add(array):
      hash = hashlib.md5()
      if len(array) == 1:
            hash.update(bytes(array[0], encoding='utf-8'))
            return hash.hexdigest()
      elif len(array) == 2:
            hash.update(bytes(array[0], encoding='utf-8'))
            hash.update(bytes(array[1], encoding='utf-8'))
            return hash.hexdigest()         

def Merkle(array):
      print(array)
      array.reverse()
      if len(array) == 1:
            return array
      t =[]
      res = []
      index = -1
      while(len(array) > 0):
            index += 1
            item = array.pop()
            if index % 2 == 0:
                  t.append(item)
                  if len(array) == 0:
                        res.append(add(t))
                        t = []
            else:
                  t.append(item)
                  res.append(add(t))
                  t = []
      
      Merkle(res)

time1 = time.time()
data = ['a','b','c','d','e','f','g','h','i','j','k']
Hdata = data_hash(data)
Merkle(Hdata)
time2 = time.time()
time = time2 - time1
print(time)
