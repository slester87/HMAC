import hashlib


def test_sha_256(message):
    return hashlib.sha256(message).hexdigest()

def main():
    fh = open("I.txt",'rb')

    print(test_sha_256(fh.read()))

main()