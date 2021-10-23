import tkinter as tk
import hashlib as hl
import hmac
from Crypto.Cipher import AES
import mysql.connector as conn
from _mysql_connector import MySQLInterfaceError

pepper = hl.sha256(b"VewwySecretKey").hexdigest()
dbhost = "localhost"
dbuser = "root"

#def tryRegister():


loginPage = tk.Tk()
loginPage.title("Portfel haseł v0.2")

try:
    db = conn.connect(host=dbhost, user=dbuser)
    connectLabel = tk.Label(loginPage, text="Połączono z bazą danych", fg="green").pack()
except (MySQLInterfaceError, conn.errors.DatabaseError):
    connectLabel = tk.Label(loginPage, text="Nie udało się połączyć z bazą danych", fg="red").pack()

loginInfoLabel = tk.Label(loginPage, text="Logowanie").pack()
loginLoginLabel = tk.Label(loginPage, text="Login").pack()
loginLoginInput = tk.Entry(loginPage).pack()
loginPassLabel = tk.Label(loginPage, text="Hasło").pack()
loginPassInput = tk.Entry(loginPage, show='\u2022').pack()

hashChoice = tk.IntVar()
hashChoice.set(1)
hashLabel = tk.Label(loginPage, text="Sposób hashowania").pack()
hashSHAradio = tk.Radiobutton(loginPage, text="AES", variable=hashChoice, value=1).pack()
hashHMACradio = tk.Radiobutton(loginPage, text="HMAC", variable=hashChoice, value=2).pack()

loginButton = tk.Button(loginPage, text="Zaloguj").pack()
loginRegisterButton = tk.Button(loginPage, text="Zarejestruj").pack()

tk.mainloop()
