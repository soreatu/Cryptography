# -*- coding: utf-8 -*-

'  Shift(or Caesar) Cipher  '
# Description: One type of *substitution cipher*
# Idea: shift letters in alphabet

# +-----------------------------+
# |   Def.   Shift Cipher       |
# |   Let x, y, k ∈ Z₂₆          |
# |   Enc: eₖ(x) ≡ x + k mod 26  |
# |   Dec: dₖ(y) ≡ y - k mod 26  |
# +------------------------------+

'''Encryption & Decryption'''
def shift_enc(m, k):
    '''
    Encryption of shift cipher

    :param str m: The message to be encrypted
    :param int k: Key of encrytion, offset of shifting
    :return: cipher after shifting
    :rtype str
    :raises AssertError: if not all characters in m are alphabetic
    :raises AssertError: if k is not in interval (-26, 26)
    '''
    assert m.isalpha()
    assert k > -26 and k < 26
    result = ""
    for ch in m:
        if ch.islower():
            result += chr(( ord(ch) - 97 + k ) % 26 + 97)
        else: # isupper
            result += chr(( ord(ch) - 65 + k ) % 26 + 65)
    return result

def shift_dec(c, k):
    '''
    Decryption of shift cipher

    :param str c: The cipher to be decrypted
    :param int k: Key of decryption, offset of shifting
    :return: message after shifting
    :rtype str
    :raises AssertError: if not all characters in m are alphabetic
    :raises AssertError: if k is not in interval (-26, 26)
    '''
    assert c.isalpha()
    assert k > -26 and k < 26
    result = ""
    for ch in c:
        if ch.islower():
            result += chr(( ord(ch) - 97 - k ) % 26 + 97)
        else: # isupper
            result += chr(( ord(ch) - 65 - k ) % 26 + 65)
    return result


'''Attack'''
# There are generally two kinds of ways to attack the *shift cipher*:
# - **Frequency analysis** which is a general attack against *substitution cipher*.
# - **Brute-force** for the *key space* only contains 26 possible keys.

# For Brute-force Attack
def alphabet_shift(c):
    '''
    Print all the possible message encrypted by alphabet
    
    :param str c: The cipher needed to be recovered
    :no return
    :side effect: Print something(type `str`) on the console
    '''
    for i in range(26):
        result = ""
        for ch in c:
            if ch.islower():
                result += chr(( ord(ch) - 97 + i ) % 26 + 97)
            elif ch.isupper():
                result += chr((ord(ch) - 65 + i) % 26 + 65)
            else:
                result += ch
        print(result)

def ascii_shift(c):
    '''
    Print all the possible message encrypted by ascii table

    :param str c: The cipher to be recovered
    :no return
    :side effect: Print something(type `bytes`) on the console
    '''
    for i in range(128):
        result = b""
        for ch in c:
            result += bytes([(ord(ch) + i) % 128])
        print(result)


# Basically, `flag` is in the form of "flag{...}",
# where offset of the first 5 letters is '6, -11, 6, 20'.
# Usually, some messages are not in that way encrypted,
# the *encryption function* is more or less modified, but
# it is still shift cipher and can be broken, and it helps
# a lot to analyse the offset of each letters to find in
# which way the message is encrypted.
 
# For offset analysis
def l_offset(ch1, ch2):
    '''
    Calculate the ascii offset between the two characters ch1 and ch2

    :param str ch1: The first character
    :param str ch2: The second character
    :return: the offset between the two characters
    :rtype: int
    '''
    return ord(ch1) - ord(ch2)

def s_offset(c):
    '''
    Print the offsets of every adjacent letter in the cipher

    :param str c: The cipher to be analysed
    :no return
    :side effect: Print something on the console
    '''
    for i in range(len(c)-1):
        print(l_offset(c[i + 1], c[i]), end=' ')


# For frequency analysis
# The website 'https://quipqiup.com/' is quite useful.


'''Test'''
def test():
    message = "Caesar Cipher"
    key = 3
    cipher = shift_enc(message, key)
    print("Messgae: " + message)
    print("Cipher: " + cipher)
    print("Recover: " + shift_dec(cipher, key))
    print("--------------------")
    print("Attack:")
    alphabet_shift(cipher)

if __name__ == "__main__":
    test()