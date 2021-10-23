import tkinter as tk
import hashlib as hl
import hmac
import _mysql_connector
from Crypto.Cipher import AES
import mysql.connector as conn
import random
import string

pepper = hl.sha256(b"VewwySecretKey")
binpepper = pepper.digest()
pepper = pepper.hexdigest()
dbhost = "localhost"
dbuser = "root"
dbdatabase = "fspw"
db = None

loginPage = tk.Tk()
loginPage.geometry("380x270")
loginPage.title("Portfel haseł v0.3")

loginInfoLabel = tk.Label(loginPage, text="Logowanie").pack()
loginLoginLabel = tk.Label(loginPage, text="Login").pack()
loginLoginInput = tk.Entry(loginPage)
loginLoginInput.pack()
loginPassLabel = tk.Label(loginPage, text="Hasło").pack()
loginPassInput = tk.Entry(loginPage, show='\u2022')
loginPassInput.pack()

hashChoice = tk.IntVar()
hashChoice.set(1)
hashLabel = tk.Label(loginPage, text="Sposób przechowywania hasła").pack()
hashSHAradio = tk.Radiobutton(loginPage, text="SHA+AES", variable=hashChoice, value=1).pack()
hashHMACradio = tk.Radiobutton(loginPage, text="HMAC", variable=hashChoice, value=2).pack()


def vault(username, masterkey, salt):
    print(username, masterkey, salt)


def createsalt(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def tryregister():
    username = loginLoginInput.get()
    password = loginPassInput.get()
    salt = createsalt(16)
    password = password + salt
    if hashChoice.get() == 1:
        storage = '1'
        password = hl.sha512(password.encode('UTF-8')).hexdigest()
        print(password)
        print("nonce: ")
        print(password.encode('UTF-8'))
        cipher = AES.new(binpepper, AES.MODE_EAX, nonce=password.encode('UTF-8'))
        password = cipher.encrypt(password.encode('UTF-8'))
        print("zaszyfowany")
        print(password)
        password = password.hex()
        print("zaszyfrowany hex")
        print(password)
    else:
        storage = '2'
        password = hmac.new(pepper.encode('UTF-8'), password.encode('UTF-8'), hl.sha512).hexdigest()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM `users` WHERE `login` = '"+username+"'")
    res = cursor.fetchall()
    if res:
        tk.Label(loginPage, text="Taki użytkownik już istnieje!", fg="red").pack()
    else:
        cursor.execute("INSERT INTO `users` (`id`, `login`, `password_hash`, `salt`, `storage`) VALUES (NULL, '" +
                       username + "', '" + password + "', '" + salt + "', '" + storage + "');")
        tk.Label(loginPage, text="Zarejestrowano! Możesz się teraz zalogować.", fg="green").pack()


def trylogin():
    username = loginLoginInput.get()
    password = loginPassInput.get()
    masterkey = password
    cursor = db.cursor()
    cursor.execute("SELECT * FROM `users` WHERE `login` = '"+username+"'")
    res = cursor.fetchall()
    if res:
        salt = res[0][3]
        password = password + salt
        print("pass+salt: " + password)
        if res[0][4] == hashChoice.get():
            if hashChoice.get() == 1:
                hashpassword = hl.sha512(password.encode('UTF-8')).hexdigest()
                cipher = AES.new(binpepper, AES.MODE_EAX, nonce=hashpassword.encode('UTF-8'))
                password = cipher.encrypt(hashpassword.encode('UTF-8')).hex()
            else:
                password = hmac.new(pepper.encode('UTF-8'), password.encode('UTF-8'), hl.sha512).hexdigest()
            if password == res[0][2]:
                tk.Label(loginPage, text="Zalogowano!", fg="green").pack()
                vault(username, masterkey, salt)
            else:
                tk.Label(loginPage, text="Nieprawidłowe hasło", fg="red").pack()
        else:
            tk.Label(loginPage, text="Nieprawidłowy algorytm przechowywania hasła dla tego konta", fg="red").pack()
    else:
        tk.Label(loginPage, text="Taki użytkownik nie istnieje!", fg="red").pack()


try:
    db = conn.connect(host=dbhost, user=dbuser, database=dbdatabase)
    db.autocommit = True
    connectLabel = tk.Label(loginPage, text="Połączono z bazą danych", fg="green").pack()
    loginButton = tk.Button(loginPage, text="Zaloguj", command=trylogin).pack()
    loginRegisterButton = tk.Button(loginPage, text="Zarejestruj", command=tryregister).pack()
except (_mysql_connector.MySQLInterfaceError, conn.errors.DatabaseError):
    connectLabel = tk.Label(loginPage, text="Nie udało się połączyć z bazą danych", fg="red").pack()

tk.mainloop()
