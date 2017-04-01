# -*- coding: utf-8 -*-

import base64, requests, json
from Crypto.Cipher import AES
from Crypto import Random

class KeePassHTTP:
    def __init__( self, passphrase, id=__name__ ):
        """
        Associates to Keepass if not set
        """
        self.id = id
        self.key = self.generate_key( passphrase )
        self.api = 'http://localhost:19455'
        self.test_associate() or self.associate()

    def pad( self, s ):
        """
        Returns PKCS5 padded value
        """
        return  s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    def unpad( self, s ):
        """
        Returns PKCS5 unpadded value
        """
        return s[0:-ord(s[-1])]

    def encrypt( self, raw, iv ):
        """
        Returns base64 encoded encrypted value
        """
        aes = AES.new( base64.b64decode(self.key), AES.MODE_CBC, base64.b64decode(iv) )
        enc = aes.encrypt( self.pad(raw) )
        return base64.b64encode(enc)

    def decrypt( self, enc, iv ):
        """
        Requires base64 encoded param to decrypt
        """
        aes = AES.new( base64.b64decode(self.key), AES.MODE_CBC, base64.b64decode(iv) )
        raw = aes.decrypt( base64.b64decode(enc) )
        return self.unpad(raw)

    def generate_key( self, raw ):
        """
        Returns base64 encoded PKCS5 padded value
        """
        raw = self.pad( raw )
        return base64.b64encode(raw)

    def generate_iv( self ):
        """
        Returns base64 encoded encrypted tuple
        """
        iv = Random.new().read(AES.block_size);
        iv = base64.b64encode(iv)
        verifier = self.encrypt( iv, iv )
        return iv, verifier

    def associate( self ):
        """
        Returns boolean
        """
        request_type = 'associate'
        iv, verifier = self.generate_iv()
        payload = {
            'RequestType': request_type,
            'Id': self.id,
            'Nonce': iv,
            'Verifier': verifier,
            'Key': self.key
            }
        response = self.post( payload )
        return response['Success']

    def test_associate( self ):
        """
        Returns boolean
        """
        request_type = 'test-associate'
        iv, verifier = self.generate_iv()
        payload = {
            'RequestType': request_type,
            'Id': self.id,
            'Nonce': iv,
            'Verifier': verifier
            }
        response = self.post( payload )
        return response['Success']

    def generate_password( self ):
        """
        Returns dictionary of entries
        """
        request_type = 'generate-password'
        iv, verifier = self.generate_iv()
        payload = {
            'RequestType': request_type,
            'Id': self.id,
            'Nonce': iv,
            'Verifier': verifier
            }
        response = self.post( payload )
        return response['Entries']

    def get_all_logins( self ):
        request_type = 'get-all-logins'
        iv, verifier = self.generate_iv()
        payload = {
            'RequestType': request_type,
            'Id': self.id,
            'Nonce': iv,
            'Verifier': verifier
            }
        response = self.post( payload )
        return response['Entries']

    def get_logins( self, url, submiturl=None, realm=None ):
        request_type = 'get-logins'
        iv, verifier = self.generate_iv()
        url = self.encrypt( url, iv )
        payload = {
            'RequestType': request_type,
            'Id': self.id,
            'Nonce': iv,
            'Verifier': verifier,
            'Url': url
            }
        if submiturl is not None:
            payload['SubmitUrl'] = self.encrypt( submiturl, iv );
        if realm is not None:
            payload['Realm'] = self.encrypt( realm, iv );
        response = self.post( payload )
        return response['Entries']

    def set_login( self, url, login, password, uuid=None ):
        request_type = 'set-login'
        iv, verifier = self.generate_iv()
        url = self.encrypt( url, iv )
        login = self.encrypt( login, iv )
        password = self.encrypt( password, iv )
        payload = {
            'RequestType': request_type,
            'Id': self.id,
            'Nonce': iv,
            'Verifier': verifier,
            'Url': url,
            'Login': login,
            'Password': password
            }
        if uuid is not None:
            payload['Uuid'] = self.encrypt( uuid, iv )
        response = self.post( payload )
        return response['Success']

    def post( self, payload ):
        r = requests.post( self.api, json=payload )
        response = r.json()
        if r.status_code != requests.codes.ok:
            raise Exception('Error Occured', r.status_code, r.text)
        if 'Entries' in response:
            iv, verifier = ( response['Nonce'], response['Verifier'] )
            for entry in response['Entries']:
                for attr, val in entry.items():
                    entry[attr] = self.decrypt( val, iv )
        return response
