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
loginPage.title("Portfel haseł b58")

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


def showInfo(parent, text, color):
    for child in parent.winfo_children():
        child.destroy()
    tk.Label(parent, text=text, fg=color).pack()


def hashandencrypt(password):
    password = hl.sha512(password.encode('UTF-8')).hexdigest()
    cipher = AES.new(binpepper, AES.MODE_EAX, nonce=password.encode('UTF-8'))
    password = cipher.encrypt(password.encode('UTF-8'))
    password = password.hex()
    return password


def hashhmac(password):
    password = hmac.new(pepper.encode('UTF-8'), password.encode('UTF-8'), hl.sha512).hexdigest()
    return password


def encrypt(password, masterkey):
    # AES encrypt here
    print("encrypt")


def decrypt(password, masterkey):
    print("decrypt")


def changepassword():
    print("zmiana")


def vault(userid, username, masterkey, salt):

    print("Logged as:", userid, username, masterkey, salt)
    vaultPage = tk.Tk()
    vaultPage.geometry("380x270")
    vaultPage.title("Zalogowano jako: " + username)
    loginPage.withdraw()

    def closeProgram():
        loginPage.destroy()
        vaultPage.destroy()

    vaultPage.protocol('WM_DELETE_WINDOW', closeProgram)

    def logout():
        vaultPage.destroy()
        loginPage.deiconify()
        loginLoginInput.delete(0, 'end')
        loginPassInput.delete(0, 'end')
        showInfo(infoBox, "", "black")

    def logoutandclose():
        vaultPage.destroy()
        loginPage.destroy()

    dataFrame = tk.LabelFrame(vaultPage, text="Zalogowano", fg="green")
    tk.Label(dataFrame, text="Zalogowano jako: " + username + " (" + str(userid) + ")").pack()
    dataFrame.pack(fill="x")

    passwordFrame = tk.LabelFrame(vaultPage, text="Hasła")
    passwordFrame.pack()

    vaultMenu = tk.Menu(vaultPage)
    logoutSubmenu = tk.Menu(vaultMenu, tearoff=False)
    logoutSubmenu.add_command(label="Wyloguj", command=logout)
    logoutSubmenu.add_command(label="Wyloguj i wyjdź", command=logoutandclose)
    vaultMenu.add_cascade(label="Wyloguj", menu=logoutSubmenu)
    vaultMenu.add_command(label="Zmień hasło", command=changepassword)
    vaultPage.config(menu=vaultMenu)


def createsalt(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def tryregister():
    username = loginLoginInput.get()
    if len(username) < 3:
        showInfo(infoBox, "Nazwa użytkownika musi mieć co najmniej 3 znaki!", "red")
        return None
    password = loginPassInput.get()
    if len(password) < 8:
        showInfo(infoBox, "Hasło jest za krótkie (co najmniej 8 znaków)!", "red")
        return None
    salt = createsalt(16)
    password = password + salt
    if hashChoice.get() == 1:
        storage = '1'
        password = hashandencrypt(password)
    else:
        storage = '2'
        password = hashhmac(password)
    cursor = db.cursor()
    cursor.execute("SELECT * FROM `users` WHERE `login` = '"+username+"'")
    res = cursor.fetchall()
    if res:
        showInfo(infoBox, "Taki użytkownik już istnieje", "red")
    else:
        cursor.execute("INSERT INTO `users` (`id`, `login`, `password_hash`, `salt`, `storage`) VALUES (NULL, '" +
                       username + "', '" + password + "', '" + salt + "', '" + storage + "');")
        showInfo(infoBox, "Zarejestrowano! Możesz się teraz zalogować.", "green")


def trylogin():
    username = loginLoginInput.get()
    if len(username) < 3:
        showInfo(infoBox, "Nazwa użytkownika musi mieć co najmniej 3 znaki!", "red")
        return 0
    password = loginPassInput.get()
    masterkey = password
    cursor = db.cursor()
    cursor.execute("SELECT * FROM `users` WHERE `login` = '"+username+"'")
    res = cursor.fetchall()
    if res:
        salt = res[0][3]
        password = password + salt
        if res[0][4] == hashChoice.get():
            if hashChoice.get() == 1:
                password = hashandencrypt(password)
            else:
                password = hashhmac(password)
            if password == res[0][2]:
                showInfo(infoBox, "Zalogowano!", "green")
                vault(res[0][0], username, masterkey, salt)
            else:
                showInfo(infoBox, "Nieprawidłowe hasło", "red")
        else:
            showInfo(infoBox, "Nieprawidłowy algorytm przechowywania hasła dla tego konta", "red")
    else:
        showInfo(infoBox, "Taki użytkownik nie istnieje!", "red")


try:
    db = conn.connect(host=dbhost, user=dbuser, database=dbdatabase)
    db.autocommit = True
    connectLabel = tk.Label(loginPage, text="Połączono z bazą danych", fg="green").pack()
    loginButton = tk.Button(loginPage, text="Zaloguj", command=trylogin).pack()
    loginRegisterButton = tk.Button(loginPage, text="Zarejestruj", command=tryregister).pack()
    infoBox = tk.Frame(loginPage)
    infoBox.pack(fill="x")
except (_mysql_connector.MySQLInterfaceError, conn.errors.DatabaseError):
    connectLabel = tk.Label(loginPage, text="Nie udało się połączyć z bazą danych", fg="red").pack()

tk.mainloop()
