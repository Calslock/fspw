# fspw
fspw (_free secure password wallet_) is a local password wallet created in python3. It uses local or remote MySQL 
database to store encrypted passwords.

##  Usage
Clone this repository. Create new MySQL database and import `fspw.sql`. Finally, change credentials in `wallet.py` in
lines 38-41. You may also want to change secret key (line 35).

## Database
After importing SQL file, 2 accounts will be created, with 2 passwords in vault each:
```
test:testpass
Hashing method: SHA+AES

testhmac:testhmac
Hashing method: HMAC
```