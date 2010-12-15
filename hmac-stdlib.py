import hmac
import sys
import hashlib

def hmac_sha1(key, message):
    """
    >>> from codecs import encode
    >>> encode(hmac_sha1('\x0b' * 20, 'Hi There'), 'hex')
    'b617318655057264e28bc0b6fb378c8ef146be00'

    """
    massage = hmac.new(key, message, hashlib.sha1)
    return massage.digest()

if __name__ == '__main__':
    from codecs import encode

    key, message = sys.argv[1], open(sys.argv[2]).read()
    print encode(hmac_sha1(key, message), 'hex')
