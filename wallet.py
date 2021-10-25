# python3
# (c) 2021 Karol Buchajczuk (admin@calslock.net) on GPLv3 and AGPLv3 where applicable
# requires tk
import tkinter as tk
import hashlib as hl
import hmac
# requires mysql-connector-python
import _mysql_connector
# requires pycryptodome
from Crypto.Cipher import AES
import mysql.connector as conn
import random
import string
import webbrowser


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

login_page = tk.Tk()
login_page.geometry("380x270")
login_page.title("fspw b289")

login_info_label = tk.Label(login_page, text="Sign in").pack()
login_login_label = tk.Label(login_page, text="Login").pack()
login_login_input = tk.Entry(login_page)
login_login_input.pack()
login_pass_label = tk.Label(login_page, text="Password").pack()
login_pass_input = tk.Entry(login_page, show='\u2022')
login_pass_input.pack()

hash_choice = tk.IntVar()
hash_choice.set(1)
hash_label = tk.Label(login_page, text="DB hashing mode").pack()
hash_sha_radio = tk.Radiobutton(login_page, text="SHA+AES", variable=hash_choice, value=1).pack()
hash_hmac_radio = tk.Radiobutton(login_page, text="HMAC", variable=hash_choice, value=2).pack()


def show_info(parent, text, color):
    for child in parent.winfo_children():
        child.destroy()
    tk.Label(parent, text=text, fg=color).pack()


def hash_and_encrypt(password) -> str:
    password = hl.sha512(password.encode('UTF-8')).hexdigest()
    cipher = AES.new(binpepper, AES.MODE_EAX, nonce=password.encode('UTF-8'))
    password = cipher.encrypt(password.encode('UTF-8'))
    password = password.hex()
    return password


def hash_hmac(password) -> str:
    password = hmac.new(pepper.encode('UTF-8'), password.encode('UTF-8'), hl.sha512).hexdigest()
    return password


def encrypt(password, masterkey) -> bytes:
    mkhash = hl.md5(masterkey.encode('UTF-8')).digest()
    cipher = AES.new(mkhash, AES.MODE_EAX, nonce=masterkey.encode('UTF-8'))
    encrypted = cipher.encrypt(password.encode('UTF-8'))
    return encrypted


def decrypt(encpassword, masterkey) -> str:
    mkhash = hl.md5(masterkey.encode('UTF-8')).digest()
    cipher = AES.new(mkhash, AES.MODE_EAX, nonce=masterkey.encode('UTF-8'))
    decrypted = cipher.decrypt(encpassword)
    decrypted = decrypted.decode('UTF-8')
    return decrypted


def get_input_and_decrypt(entry: tk.Entry, passwordarg, masterkey):
    passhex = passwordarg.hex()
    if entry.get() == passhex:
        entry.delete(0, 'end')
        entry.insert(0, decrypt(passwordarg, masterkey))
    else:
        entry.delete(0, 'end')
        entry.insert(0, passhex)


def close(widget: tk.Toplevel):
    widget.destroy()


def vault(userid, username, masterkey):
    vault_page = tk.Tk()
    vault_page.geometry("380x300")
    vault_page.title("Logged as: " + username)
    login_page.withdraw()

    def closeprogram():
        login_page.destroy()
        vault_page.destroy()

    vault_page.protocol('WM_DELETE_WINDOW', closeprogram)

    def logout():
        vault_page.destroy()
        login_page.deiconify()
        login_login_input.delete(0, 'end')
        login_pass_input.delete(0, 'end')
        show_info(infoBox, "", "black")

    def logoutandclose():
        vault_page.destroy()
        login_page.destroy()

    def add_password():
        add_password_window = tk.Toplevel(vault_page)
        add_password_window.title("Add password to vault")
        add_password_window.columnconfigure(0, weight=1)
        add_password_window.columnconfigure(1, weight=10)

        tk.Label(add_password_window, text="Add password: ", anchor="w").grid(column=0, row=0, sticky=tk.W, padx=5,
                                                                             pady=5)
        mini_nfo = tk.Label(add_password_window, anchor="e")
        mini_nfo.grid(column=1, row=0, sticky=tk.E, padx=5, pady=5)
        tk.Label(add_password_window, text="Name (required): ", anchor="w").grid(column=0, row=1, sticky=tk.W, padx=5,
                                                                                  pady=5)
        tk.Label(add_password_window, text="Website: ", anchor="w").grid(column=0, row=2, sticky=tk.W, padx=5, pady=5)
        tk.Label(add_password_window, text="Password (required):", anchor="w").grid(column=0, row=3, sticky=tk.W, padx=5, pady=5)

        add_pass_name = tk.Entry(add_password_window)
        add_pass_name.grid(column=1, row=1, padx=5, pady=5)
        add_pass_site = tk.Entry(add_password_window)
        add_pass_site.grid(column=1, row=2, padx=5, pady=5)
        add_pass_pass = tk.Entry(add_password_window, show='\u2022')
        add_pass_pass.grid(column=1, row=3, padx=5, pady=5)

        def add_pass_to_database():
            website_exists = True
            name = add_pass_name.get()
            if len(name) < 3:
                show_info(mini_nfo, "Name must be at least 3 characters long!", "red")
                return None
            website = add_pass_site.get()
            if len(website) == 0:
                website_exists = False
            password = add_pass_pass.get()
            if len(password) == 0:
                show_info(mini_nfo, "Password cannot be empty!", "red")
                return None
            encrypted = encrypt(password, masterkey)
            cursor = db.cursor()
            if website_exists:
                cursor.execute("INSERT INTO `vault` (`id`, `userid`, `name`, `website`, `password`) VALUES (NULL, '" +
                               str(userid) + "', '" + name + "' , '" + website + "', 0x" + encrypted.hex() + "); ")
            else:
                cursor.execute("INSERT INTO `vault` (`id`, `userid`, `name`, `website`, `password`) VALUES (NULL, '" +
                               str(userid) + "', '" + name + "' , NULL, 0x" + encrypted.hex() + "); ")
            refresh()
            close(add_password_window)

        add_pass_confirm = tk.Button(add_password_window, text="Confirm", command=add_pass_to_database)
        add_pass_confirm.grid(column=0, row=4, sticky=tk.W, padx=5, pady=5)
        add_pass_cancel = tk.Button(add_password_window, text="Cancel", command=lambda: close(add_password_window))
        add_pass_cancel.grid(column=1, row=4, sticky=tk.E, padx=5, pady=5)

    data_frame = tk.LabelFrame(vault_page, text="fspw b289", fg="green")
    tk.Label(data_frame, text="Signed as: " + username + " (" + str(userid) + ")").pack()
    data_frame.pack(fill="x")

    add_password_button = tk.Button(vault_page, text="Add password to vault", command=add_password)
    add_password_button.pack()

    password_frame = ScrollableFrame(vault_page)
    password_frame.pack()
    password_frame.scrollable_frame.config(text="Passwords")

    def remove_password(passid: int, passname: str):
        remove_password_window = tk.Toplevel(vault_page)
        remove_password_window.title("Delete password")
        button_frame = tk.LabelFrame(remove_password_window, text="Are you sure you want to remove: " + passname + "?",
                                     fg="red")
        button_frame.pack(fill="x")
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)

        def confirm():
            cursor = db.cursor()
            cursor.execute("DELETE FROM `vault` WHERE `vault`.`id` = " + str(passid))
            refresh()
            close(remove_password_window)

        confirm_button = tk.Button(button_frame, text="Confirm", command=confirm)
        confirm_button.grid(column=0, row=0, padx=5, pady=5, sticky=tk.W)
        cancel_button = tk.Button(button_frame, text="Cancel", command=lambda: close(remove_password_window))
        cancel_button.grid(column=1, row=0, padx=5, pady=5, sticky=tk.E)

    def change_password():
        change_password_window = tk.Toplevel(vault_page)
        change_password_window.title("Change password")

        cp_frame = tk.LabelFrame(change_password_window, text="Changing password for: " + username, fg="red")
        cp_frame.pack(fill="x")
        cp_frame.grid_columnconfigure(0, weight=1)
        cp_frame.grid_columnconfigure(1, weight=1)

        tk.Label(cp_frame, text="New password:").grid(column=0, row=0, padx=5, pady=5, sticky=tk.W)
        tk.Label(cp_frame, text="Repeat new password:").grid(column=0, row=1, padx=5, pady=5, sticky=tk.W)

        newpass = tk.Entry(cp_frame, show='\u2022')
        newpass.grid(column=1, row=0, padx=5, pady=5, sticky=tk.E)
        confnewpass = tk.Entry(cp_frame, show='\u2022')
        confnewpass.grid(column=1, row=1, padx=5, pady=5, sticky=tk.E)
        newsalt = createsalt(16)

        def confirm():
            if newpass.get() == confnewpass.get() and len(newpass.get()) != 0 and len(newpass.get()) >= 8:
                cursor = db.cursor()
                confpass = newpass.get()
                confpasssalt = confpass + newsalt
                newhash = hash_and_encrypt(confpasssalt)
                cursor.execute("UPDATE `users` SET `password_hash` = '" + newhash + "', `salt` = '" + newsalt +
                               "' WHERE `users`.`id` = " + str(userid))
                cursor = db.cursor()
                cursor.execute("SELECT * FROM `vault` WHERE `userid` = '" + str(userid) + "'")
                passwords = cursor.fetchall()
                for entry in passwords:
                    passid = entry[0]
                    encryptedpass = bytes(entry[4])
                    decryptedpass = decrypt(encryptedpass, masterkey)
                    encryptedagain = encrypt(decryptedpass, confpass)
                    cursor.execute("UPDATE `vault` SET `password` = 0x" + encryptedagain.hex() +
                                   " WHERE `vault`.`id` = " + str(passid))
                close(change_password_window)
                logout()
                show_info(infoBox, "Password changed successfully!", "green")

            elif len(newpass.get()) == 0:
                cp_frame.config(text="Password cannot be empty!")
            elif len(newpass.get()) < 8:
                cp_frame.config(text="Password is too short!")
            else:
                cp_frame.config(text="Passwords aren't exact!")

        confirm_button = tk.Button(cp_frame, text="Confirm", command=confirm)
        confirm_button.grid(column=0, row=2, padx=5, pady=5, sticky=tk.W)
        cancel_button = tk.Button(cp_frame, text="Cancel", command=lambda: close(change_password_window))
        cancel_button.grid(column=1, row=2, padx=5, pady=5, sticky=tk.E)

    def refresh():
        for child in password_frame.scrollable_frame.winfo_children():
            child.destroy()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM `vault` WHERE `userid` = '" + str(userid) + "'")
        passwords = cursor.fetchall()
        for entry in passwords:
            pass_frame = tk.LabelFrame(password_frame.scrollable_frame, text=entry[2])
            pass_frame.pack(fill="x")

            pass_box_frame = tk.Frame(pass_frame)
            pass_box_frame.grid_columnconfigure(0, weight=6)
            pass_box_frame.grid_columnconfigure(1, weight=1)
            pass_box_frame.pack(fill="x")

            website_label = tk.Label(pass_box_frame, text=entry[3], fg="blue", cursor="hand2")
            website_label.grid(column=0, row=0, padx=5, pady=5)
            website_label.bind("<Button-1>", lambda website_labell=website_label, entryl=entry[3]:
                               webbrowser.open_new("http://" + entryl))

            remove_button = tk.Button(pass_box_frame, text="Delete", command=lambda idl=entry[0], namel=entry[2]:
                                      remove_password(idl, namel))
            remove_button.grid(column=1, row=0, padx=5, pady=5)

            pass_box = tk.Entry(pass_box_frame, width=42)
            encryptedpass = bytes(entry[4])
            pass_box.insert(0, encryptedpass.hex())
            pass_box.grid(column=0, row=1, padx=5, pady=5)

            decrypt_button = tk.Button(pass_box_frame, text="Show/hide",
                                       command=lambda pass_boxl=pass_box, encryptedpassl=encryptedpass:
                                       get_input_and_decrypt(pass_boxl, encryptedpassl, masterkey))
            decrypt_button.grid(column=1, row=1, padx=5, pady=5)

    vault_menu = tk.Menu(vault_page)
    logout_submenu = tk.Menu(vault_menu, tearoff=False)
    logout_submenu.add_command(label="Logout", command=logout)
    logout_submenu.add_command(label="Logout and exit", command=logoutandclose)
    vault_menu.add_cascade(label="Logout", menu=logout_submenu)
    vault_menu.add_command(label="Change password", command=change_password)
    vault_page.config(menu=vault_menu)
    refresh()


def createsalt(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def tryregister():
    username = login_login_input.get()
    if len(username) < 3:
        show_info(infoBox, "Username must be at least 3 characters long!", "red")
        return None
    password = login_pass_input.get()
    if len(password) < 8:
        show_info(infoBox, "Password must be at least 8 characters long!", "red")
        return None
    salt = createsalt(16)
    password = password + salt
    if hash_choice.get() == 1:
        storage = '1'
        password = hash_and_encrypt(password)
    else:
        storage = '2'
        password = hash_hmac(password)
    cursor = db.cursor()
    cursor.execute("SELECT * FROM `users` WHERE `login` = '" + username + "'")
    res = cursor.fetchall()
    if res:
        show_info(infoBox, "User already exists!", "red")
    else:
        cursor.execute("INSERT INTO `users` (`id`, `login`, `password_hash`, `salt`, `storage`) VALUES (NULL, '" +
                       username + "', '" + password + "', '" + salt + "', '" + storage + "');")
        show_info(infoBox, "Success! You can now sign in.", "green")


def trylogin():
    username = login_login_input.get()
    if len(username) < 3:
        show_info(infoBox, "Username must be at least 3 characters long!", "red")
        return 0
    password = login_pass_input.get()
    masterkey = password
    cursor = db.cursor()
    cursor.execute("SELECT * FROM `users` WHERE `login` = '" + username + "'")
    res = cursor.fetchall()
    if res:
        salt = res[0][3]
        password = password + salt
        if res[0][4] == hash_choice.get():
            if hash_choice.get() == 1:
                password = hash_and_encrypt(password)
            else:
                password = hash_hmac(password)
            if password == res[0][2]:
                show_info(infoBox, "Signed in!", "green")
                vault(res[0][0], username, masterkey)
            else:
                show_info(infoBox, "Wrong password!", "red")
        else:
            show_info(infoBox, "This account uses different hashing method!", "red")
    else:
        show_info(infoBox, "User doesn't exist!", "red")


try:
    db = conn.connect(host=dbhost, user=dbuser, database=dbdatabase)
    db.autocommit = True
    connectLabel = tk.Label(login_page, text="Connected with MySQL database", fg="green").pack()
    loginButton = tk.Button(login_page, text="Sign in", command=trylogin).pack()
    loginRegisterButton = tk.Button(login_page, text="Register", command=tryregister).pack()
    infoBox = tk.Frame(login_page)
    infoBox.pack(fill="x")
except (_mysql_connector.MySQLInterfaceError, conn.errors.DatabaseError):
    connectLabel = tk.Label(login_page, text="Couldn't connect to database", fg="red").pack()

tk.mainloop()
