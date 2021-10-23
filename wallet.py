import tkinter as tk
import hashlib as hl
import hmac
import _mysql_connector
from Crypto.Cipher import AES
import mysql.connector as conn
import random
import string

pepper = hl.sha256(b"VewwySecretKey").hexdigest()
dbhost = "localhost"
dbuser = "root"
dbdatabase = "fspw"
db = None

loginPage = tk.Tk()
loginPage.geometry("320x270")
loginPage.title("Portfel haseł v0.2")

loginInfoLabel = tk.Label(loginPage, text="Logowanie").pack()
loginLoginLabel = tk.Label(loginPage, text="Login").pack()
loginLoginInput = tk.Entry(loginPage)
loginLoginInput.pack()
loginPassLabel = tk.Label(loginPage, text="Hasło").pack()
loginPassInput = tk.Entry(loginPage, show='\u2022')
loginPassInput.pack()

hashChoice = tk.IntVar()
hashChoice.set(1)
hashLabel = tk.Label(loginPage, text="Sposób hashowania").pack()
hashSHAradio = tk.Radiobutton(loginPage, text="AES", variable=hashChoice, value=1).pack()
hashHMACradio = tk.Radiobutton(loginPage, text="HMAC", variable=hashChoice, value=2).pack()

def createSalt(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(length))

def tryRegister():
    username = loginLoginInput.get()
    password = loginPassInput.get()
    salt = createSalt(16)
    password = password + salt
    if hashChoice.get() == 1:
        storage = '1'
        password = hl.sha512(password.encode('UTF-8')).hexdigest()
    else:
        storage = '2'
        password = hmac.new(pepper.encode('UTF-8'), password.encode('UTF-8'), hl.sha512).hexdigest()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM `users` WHERE `login` = '"+username+"'")
    res = cursor.fetchall()
    print(cursor.fetchall())
    if res:
        tk.Label(loginPage, text="Taki użytkownik już istnieje!").pack()
    else:
        cursor.execute("INSERT INTO `users` (`id`, `login`, `password_hash`, `salt`, `storage`) VALUES (NULL, '"+username+"', '"+password+"', '"+salt+"', '"+storage+"');")
        tk.Label(loginPage, text="Zarejestrowano! Możesz się teraz zalogować.").pack()

try:
    db = conn.connect(host=dbhost, user=dbuser, database=dbdatabase)
    db.autocommit = True
    connectLabel = tk.Label(loginPage, text="Połączono z bazą danych", fg="green").pack()
    loginButton = tk.Button(loginPage, text="Zaloguj").pack()
    loginRegisterButton = tk.Button(loginPage, text="Zarejestruj", command=tryRegister).pack()
except (_mysql_connector.MySQLInterfaceError, conn.errors.DatabaseError):
    connectLabel = tk.Label(loginPage, text="Nie udało się połączyć z bazą danych", fg="red").pack()

tk.mainloop()