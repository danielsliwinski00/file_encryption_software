from Crypto.PublicKey import RSA    #RSA for asymmetric encryption
from Crypto.Random import get_random_bytes  #get_random_bytes import to generate random bytes
from Crypto.Cipher import PKCS1_OAEP    #asymmetric cipher to use with rsa
import hashlib  #simple hash for passwords
import os   #to interact with the os e.g. check/make directories
import sys
from getpass import getpass

def encrypt_file(username, user_hash):
    input_filename = input('Name of file to encrypt: ')
    decision = input('Is '+input_filename+' the correct file name? 0 for no, 1 for yes: ')
    pubkey_hash = hashlib.sha224(username.encode()).hexdigest()

    if decision == '0':
        encrypt_file(username, user_hash)

    elif decision == '1':
        public_key = RSA.import_key(open(pubkey_hash+'publickey.pem').read())
        cipher = PKCS1_OAEP.new(public_key)

        with open(input_filename, 'rb') as f:
            data = f.read()

        encrypted_data = cipher.encrypt(data)
        
        with open(input_filename+'.enc', 'wb') as f:
            f.write(encrypted_data)

        logged(username, user_hash)

    else:
        encrypt_file(username, user_hash)


def decrypt_file(username, user_hash):
    input_filename = input('Name of file to decrypt: ')
    decision = input('Is '+input_filename+' the correct file name? 0 for no, 1 for yes: ')

    name_chars = list(input_filename)
    final_name = input_filename

    chars_len = len(name_chars)

    if decision == '0':
        decrypt_file(username, user_hash)

    elif decision == '1':

        if name_chars[chars_len-4] == '.' and name_chars[chars_len-3] == 'e' and name_chars[chars_len-2] == 'n' and name_chars[chars_len-1] == 'c': #checking for .enc filename
            final_name = ''.join(str(x) for x in name_chars[:-4])

        private_key = RSA.import_key(open('./users/'+user_hash+'/'+'privkey.pem').read())
        cipher = PKCS1_OAEP.new(private_key)

        with open(input_filename, 'rb') as f:
            data = f.read()

        decrypted_data = cipher.decrypt(data)
        
        with open(final_name+'.dec', 'wb') as f:
            f.write(decrypted_data)

        print('Decrypted!')
        logged(username, user_hash)

    else:
        encrypt_file(username, user_hash)

def new_keys(username, user_hash):  #for generating a new private key   

    pubkey_hash = hashlib.sha224(username.encode()).hexdigest()

    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open('./users/'+user_hash+'/'+'privkey.pem','wb')
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open(pubkey_hash+'publickey.pem', 'wb')
    file_out.write(public_key)
    file_out.close()

    logged(username, user_hash)    #return  to logged user inerface

def logged(username, user_hash):   #logged in user inerface
    print('Welcome user '+username)
    choice = input('enter 0 to encrypt file, 1 to decrypt file, 2 to generate new key pair, 3 to see user folder/public key name, 4 to log out, 5 to exit: ')

    if choice == '0':
        encrypt_file(username, user_hash)
    elif choice == '1':
        decrypt_file(username, user_hash)
    elif choice == '2':
        new_keys(username, user_hash)
    elif choice == '3':
        print('Folder: ', user_hash, '\nPublic Key: ', hashlib.sha224(username.encode()).hexdigest())
        logged(username, user_hash)
    elif choice == '4':
        main()
    elif choice == '5':
        sys.exit()
    else:
        print('Invalid input')

def signup():
    print('Sign up')
    username = input('Enter username: ')
    password = getpass('Enter password: ')
    confirm_password = getpass('Confirm password: ')

    user_hash = hashlib.sha256(username.encode()).hexdigest()
    pubkey_hash = hashlib.sha224(username.encode()).hexdigest()

    if password == confirm_password:
        current_dir = os.getcwd()
        users_dir = os.path.join(current_dir, 'users')
        user_dir = os.path.join(users_dir, user_hash)

        if not os.path.exists(user_dir):
            os.makedirs(user_dir)

        pre_salt = str(get_random_bytes(16))
        post_salt = str(get_random_bytes(16))
        salted = pre_salt+password+post_salt
        enc = salted.encode()
        hash_pass = hashlib.sha512(enc).hexdigest()

        with open('./users/'+user_hash+'/'+'credentials.txt', 'w') as f:
            f.write(user_hash + '\n')
            f.write(hash_pass + '\n')
            f.write(pre_salt + '\n')
            f.write(post_salt)
        f.close()

        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open('./users/'+user_hash+'/'+'privkey.pem','wb')
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open(pubkey_hash+'publickey.pem', 'wb')
        file_out.write(public_key)
        file_out.close()

        login()
    else:
        print('Password is not the same as above')

    print('You have registered successfully')
    #encryptcredentials()

def login():
    print('Log in')
    username = input('Enter username: ')
    password = getpass('Enter password: ')

    user_hash = hashlib.sha256(username.encode()).hexdigest()

    if os.path.exists('./users/'+user_hash+'/'):
        with open('./users/'+user_hash+'/'+'credentials.txt', 'r') as f:
            stored_username, stored_password, pre_salt, post_salt = f.read().split('\n')
            salted = pre_salt + password + post_salt
            enc = salted.encode()
            auth_hash = hashlib.sha512(enc).hexdigest()
            
        f.close()

        if user_hash == stored_username and auth_hash == stored_password:
            print('Logged in Successfully!')
            logged(username, user_hash)
        else:
            print('Login failed! \n')
    else:
        print('user does not exist')

def main():

    current_dir = os.getcwd()
    users_dir = os.path.join(current_dir, 'users')

    if not os.path.exists(users_dir):
            os.makedirs(users_dir)

    choice = input('0 for sign up, 1 for log in, 2 to exit: ')
    if choice == '0':
        signup()
    elif choice == '1':
        login()
    elif choice == '2':
        return
    else:
        print('Invalid input')

if __name__ == '__main__':
    main()