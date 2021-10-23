import tkinter as tk
import tkinter.font as tkFont

loginpage = tk.Tk()
loginpage.title("Portfel hasel v0.1")

logininfolabel = tk.Label(loginpage, text="Logowanie")
logininfolabel.pack()

loginloginlabel = tk.Label(loginpage, text="Login")
loginloginlabel.pack()

loginlogin = tk.Entry(loginpage)
loginlogin.pack()

loginpasslabel = tk.Label(loginpage, text="Haslo")
loginpasslabel.pack()

loginpass = tk.Entry(loginpage, show='\u2022')
loginpass.pack()

tk.mainloop()
