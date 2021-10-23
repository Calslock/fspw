import tkinter as tk
import hashlib as hl
import hmac
from Crypto.Cipher import AES

pepper = "70f2a64df3aa17f5833b85c9508b23266b783b15b6562c80e4c5e92dd176b1e0"

loginPage = tk.Tk()
loginPage.title("Portfel haseł v0.1")
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



tk.mainloop()
