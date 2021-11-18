# fspw
fspw (_free as in freedom and secure password wallet_) is a local password wallet created in python3. fspw stores encrypted passwords in local or remote MySQL database. fspw is provided under GPLv3 license.

##  Usage
Clone repository. Install `tkinter`, `mysql-connector-python`, and `pycryptodome` pip packages. Create new MySQL database and import `fspw.sql` to automatically create compatible tables in database.

In `wallet.py` change database credentials in lines 38-41 and secret key in line 35.

## Database
After importing `fspw.sql`, 2 sample accounts will be created with 2 passwords in vault for each:
```
test:testpass
Hashing method: SHA+AES

testhmac:testhmac
Hashing method: HMAC
```
