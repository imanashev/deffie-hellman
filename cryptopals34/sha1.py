import hashlib


def generateHash(data):
    return hashlib.sha1(str(data).encode('UTF-8')).hexdigest()

