#!/usr/bin/python
import sys, string

def translator(ciphertext):
    print "Translate by method  I: %s" % output(decode(ciphertext, 0x4D, 0x1))
    print "Translate by method II: %s" % output(decode(ciphertext, 0x66, 0x79))

def decode(ciphertext, arg1, arg2):
    i = len(ciphertext)
    plaintext = ["" for c in range(i)]
    k = j = i - 1 
    while j >= 0:
        m = ciphertext[k]
        n = k - 1
        plaintext[k] = xor(ord(m), arg1)
        if n < 0:
            break
        j = n - 1
        plaintext[n] = xor(arg2, ord(ciphertext[n]))
        k = j
    return plaintext

def output(plaintext_list):
    result = ""
    for c in plaintext_list:
        if len(c) > 1:
            result += c
        else:
            result += c[0].encode('string-escape')
    return result

def xor(a, b):
    x = a ^ b

    # 0xB:\t, 0xC:\n, 0xF:\r
    if chr(x) in string.printable and x != 0xB and x != 0xC:
        return chr(x)
    else:
        return r'\%03o' % x

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit()
    print "The original text: %s" % sys.argv[1]
    translator(sys.argv[1].decode('string-escape'))
