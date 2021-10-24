import tkinter as tk
import hashlib as hl
import hmac
import _mysql_connector
from Crypto.Cipher import AES
import mysql.connector as conn
import random
import string


class ScrollableFrame(tk.LabelFrame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self)
        scrollbar = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        self.scrollable_frame = tk.LabelFrame(canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)


pepper = hl.sha256(b"VewwySecretKey")
binpepper = pepper.digest()
pepper = pepper.hexdigest()
dbhost = "localhost"
dbuser = "root"
dbdatabase = "fspw"
db = None

loginPage = tk.Tk()
loginPage.geometry("380x270")
loginPage.title("Portfel haseł b273")

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


def hashandencrypt(password) -> str:
    password = hl.sha512(password.encode('UTF-8')).hexdigest()
    cipher = AES.new(binpepper, AES.MODE_EAX, nonce=password.encode('UTF-8'))
    password = cipher.encrypt(password.encode('UTF-8'))
    password = password.hex()
    return password


def hashhmac(password) -> str:
    password = hmac.new(pepper.encode('UTF-8'), password.encode('UTF-8'), hl.sha512).hexdigest()
    return password


def encrypt(password, masterkey) -> bytes:
    hash = hl.md5(masterkey.encode('UTF-8')).digest()
    cipher = AES.new(hash, AES.MODE_EAX, nonce=masterkey.encode('UTF-8'))
    encrypted = cipher.encrypt(password.encode('UTF-8'))
    return encrypted


def decrypt(encpassword, masterkey) -> str:
    hash = hl.md5(masterkey.encode('UTF-8')).digest()
    cipher = AES.new(hash, AES.MODE_EAX, nonce=masterkey.encode('UTF-8'))
    decrypted = cipher.decrypt(encpassword)
    decrypted = decrypted.decode('UTF-8')
    return decrypted


def getinputanddecrypt(entry: tk.Entry, passwordarg, masterkey):
    passhex = passwordarg.hex()
    if entry.get() == passhex:
        entry.delete(0, 'end')
        entry.insert(0, decrypt(passwordarg, masterkey))
    else:
        entry.delete(0, 'end')
        entry.insert(0, passhex)


def changepassword():
    print("zmiana")


def vault(userid, username, masterkey, salt):
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

    def addPassword():
        addPasswordWindow = tk.Toplevel(vaultPage)
        addPasswordWindow.title("Dodaj hasło")
        addPasswordWindow.columnconfigure(0, weight=1)
        addPasswordWindow.columnconfigure(1, weight=10)

        tk.Label(addPasswordWindow, text="Dodaj hasło: ", anchor="w").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        miniNfo = tk.Label(addPasswordWindow, anchor="e")
        miniNfo.grid(column=1, row=0, sticky=tk.E, padx=5, pady=5)
        tk.Label(addPasswordWindow, text="Nazwa (wymagana): ", anchor="w").grid(column=0, row=1, sticky=tk.W, padx=5,
                                                                                pady=5)
        tk.Label(addPasswordWindow, text="Strona: ", anchor="w").grid(column=0, row=2, sticky=tk.W, padx=5,
                                                                                pady=5)
        tk.Label(addPasswordWindow, text="Hasło:", anchor="w").grid(column=0, row=3, sticky=tk.W, padx=5,
                                                                                pady=5)

        addPassName = tk.Entry(addPasswordWindow)
        addPassName.grid(column=1, row=1, padx=5, pady=5)
        addPassSite = tk.Entry(addPasswordWindow)
        addPassSite.grid(column=1, row=2, padx=5, pady=5)
        addPassPass = tk.Entry(addPasswordWindow, show='\u2022')
        addPassPass.grid(column=1, row=3, padx=5, pady=5)

        def addPassToDatabase():
            websiteExists = True
            name = addPassName.get()
            if len(name) < 3:
                showInfo(miniNfo, "Nazwa musi mieć co najmniej 3 znaki!", "red")
                return None
            website = addPassSite.get()
            if len(website) == 0:
                websiteExists = False
            password = addPassPass.get()
            if len(password) == 0:
                showInfo(miniNfo, "Musisz wpisać hasło!", "red")
                return None
            encrypted = encrypt(password, masterkey)
            cursor = db.cursor()
            if websiteExists:
                cursor.execute("INSERT INTO `vault` (`id`, `userid`, `name`, `website`, `password`) VALUES (NULL, '" + str(userid) + "', '" + name + "' , '" + website + "', 0x" + encrypted.hex() + "); ")
            else:
                cursor.execute("INSERT INTO `vault` (`id`, `userid`, `name`, `website`, `password`) VALUES (NULL, '" + str(userid) + "', '" + name + "' , NULL, 0x" + encrypted.hex() + "); ")
            refresh()
            addPasswordWindow.destroy()

        def close():
            addPasswordWindow.destroy()

        addPassConfirm = tk.Button(addPasswordWindow, text="Dodaj", command=addPassToDatabase)
        addPassConfirm.grid(column=0, row=4, sticky=tk.W, padx=5, pady=5)
        addPassCancel = tk.Button(addPasswordWindow, text="Anuluj", command=close)
        addPassCancel.grid(column=1, row=4, sticky=tk.E, padx=5, pady=5)

    vaultMenu = tk.Menu(vaultPage)
    logoutSubmenu = tk.Menu(vaultMenu, tearoff=False)
    logoutSubmenu.add_command(label="Wyloguj", command=logout)
    logoutSubmenu.add_command(label="Wyloguj i wyjdź", command=logoutandclose)
    vaultMenu.add_cascade(label="Wyloguj", menu=logoutSubmenu)
    vaultMenu.add_command(label="Zmień hasło", command=changepassword)
    vaultPage.config(menu=vaultMenu)

    dataFrame = tk.LabelFrame(vaultPage, text="Zalogowano", fg="green")
    tk.Label(dataFrame, text="Zalogowano jako: " + username + " (" + str(userid) + ")").pack()
    dataFrame.pack(fill="x")

    addPasswordButton = tk.Button(vaultPage, text="Dodaj hasło", command=addPassword)
    addPasswordButton.pack()

    passwordFrame = ScrollableFrame(vaultPage)
    passwordFrame.pack()
    passwordFrame.scrollable_frame.config(text = "Hasła")

    def refresh():
        for child in passwordFrame.scrollable_frame.winfo_children():
            child.destroy()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM `vault` WHERE `userid` = '" + str(userid) + "'")
        passwords = cursor.fetchall()
        for entry in passwords:
            passFrame = tk.LabelFrame(passwordFrame.scrollable_frame, text=entry[2])
            passFrame.pack(fill="x")
            websiteLabel = tk.Label(passFrame, text=entry[3])
            websiteLabel.pack()

            passBoxFrame = tk.Frame(passFrame)
            passBoxFrame.grid_columnconfigure(0, weight=6)
            passBoxFrame.grid_columnconfigure(1, weight=1)
            passBoxFrame.pack(fill="x")

            passBox = tk.Entry(passBoxFrame, width=42)
            encryptedpass = bytes(entry[4])
            passBox.insert(0, encryptedpass.hex())
            passBox.grid(column=0, row=0, padx=5, pady=5)
            decryptButton = tk.Button(passBoxFrame, text="Pokaż/ukryj",
                                      command=lambda passBox=passBox, encryptedpass=encryptedpass: getinputanddecrypt(
                                          passBox, encryptedpass, masterkey))
            decryptButton.grid(column=1, row=0, padx=5, pady=5)

    refresh()


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
