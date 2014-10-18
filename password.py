#! /usr/bin/env python3

import sqlite3
import subprocess
import os
import bcrypt
import hashlib
from Crypto.Cipher import AES
import codecs
import cherrypy
import time

pwdatabase = 'passwords.db'
# pwdatabase = ':memory:'

authKeys = dict()

login_attempts = []
login_attempt_window = 60 * 5
login_attempts_allowed = 3

cherrypy.config.update('server.conf')

# Set key expiration time in seconds
keyExpTime = 60 * 5

html_template = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="/static/style.css" rel="stylesheet" type="text/css" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Password Manager</title>
</head>
<body>
<div class="message"><a href="/">Home</a> - <a href="/logout">Logout</a> - <a href="/genpass">Generate Password</a></div>
{content}
<div class="message"><a href="/">Home</a></div>
</body>
</html>
"""

html_searchform = """\
<div class="searchform">
<form name="search" action="/search" method="get">
<input type="text" name="query">
<input type="submit" value="Search">
</form>
</div>
"""

html_addform = """\
<div class="addform">
<form name="add" action="/add" method="post">
<table>
<tr><td>Title:</td><td><input type="text" name="title"></td></tr>
<tr><td>URL:</td><td><input type="text" name="url"></td></tr>
<tr><td>Username:</td><td><input type="text" name="username"></td></tr>
<tr><td>Other:</td><td><textarea name="other"></textarea></td></tr>
</table>
<input type="submit" value="Add">
</form>
</div>
"""

html_editform = '''\
<div class="editform">
<form name="edit" action="/edit" method="post">
<input type="hidden" name="rowid" value="{rowid}">
<input type="hidden" name="confirm" value="true">
<table>
<tr><td>Title:</td><td><input type="text" name="title" value="{title}"></td></tr>
<tr><td>URL:</td><td><input type="text" name="url" value="{url}"></td></tr>
<tr><td>Username:</td><td><input type="text" name="username" value="{username}"></td></tr>
<tr><td>Password:</td><td><input type="text" name="password" value="{password}"></td></tr>
<tr><td>Other:</td><td><textarea name="other">{other}</textarea></td></tr>
</table>
<input type="submit" value="Submit">
</form>
</div>
'''

html_results = """\
<div class="results">
<table>
<tr><td>{headers[0]}:</td><td>{title}</td></tr>
<tr><td>{headers[1]}:</td><td><a target="_blank" href="{url}">{url}</a></td></tr>
<tr><td>{headers[2]}:</td><td>{username}</td></tr>
<tr><td>{headers[3]}:</td><td class="password">{password}</td></tr>
<tr><td>{headers[4]}:</td><td><pre>{other}</pre></td></tr>
</table>
<a href="/delete?rowid={rowid}">Delete</a> - <a href="/edit?rowid={rowid}">Edit</a>
</div>
"""

html_message = """\
<div class="message">{message}</div>
"""

html_confirmdelete = """\
<div class="confirmdelete">
<form name="confirmdelete" action="/delete" method="post">
<input type="hidden" name="rowid" value="{rowid}">
<input type="hidden" name="confirm" value="true">
<input type="submit" value="Confirm Delete">
</form>
</div>
"""

html_login = """\
<div class="loginform">
<form name="login" action="/login" method="post">
<input type="password" name="password">
<input type="submit" value="Login">
</form>
</div>
"""

headers = ('Title','URL','Username','Password','Other')

def encrypt(key, data):
    '''Encrypts data with AES cipher using key and random iv.'''
    if type(key) is str:
        key = key.encode()
    key = hashlib.sha256(key).digest()[:AES.block_size]
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return iv + cipher.encrypt(data)

def decrypt(key, data):
    '''Decrypt ciphertext using key'''
    if type(key) is str:
        key = key.encode()
    key = hashlib.sha256(key).digest()[:AES.block_size]
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(data)[AES.block_size:]

def loggedIn():
    '''Checks if current auth cookie is valid.'''
    cookie = cherrypy.request.cookie
    if 'auth' in cookie.keys():
        if keyValid(cookie['auth'].value):
            return True
    return False

def failedLogin():
    global login_attempts
    now = nowUnixInt()
    login_attempts.append(now)
    login_attempts = [i for i in login_attempts if i > now - login_attempt_window]
    if len(login_attempts) > login_attempts_allowed:
        loginAttemptNotify()

def loginAttemptNotify():
    subprocess.call(['./login_attempt_notify'])

def toHex(s):
    '''Returns hex string.'''
    return codecs.encode(s, 'hex').decode()

def fromHex(s):
    '''Returns bytes.'''
    return codecs.decode(s, 'hex')

def genHex(length=32):
    '''Generate random hex string.'''
    return toHex(os.urandom(length))

def nowUnixInt():
    '''Return int unix time.'''
    return int(time.time())

def newKey():
    '''Creates new key, adds it to database with timestamp, and returns it.'''
    key = genHex()
    date = nowUnixInt()
    authKeys[key] = date
    return key

def delKey(key):
    '''Removes auth key. Used for logout.'''
    if key in authKeys:
        del authKeys[key]
        return True
    return False

def keyValid(key):
    '''Return True if key is in database and is not expired. Updates timestamp if key is valid.'''
    now = nowUnixInt()
    exp_date = now - keyExpTime
    keys = [key for key in authKeys.keys()]
    for i in keys:
        if authKeys[i] < exp_date:
          del authKeys[i]
    if key not in authKeys:
        return False
    authKeys[key] = now
    return True

def pwSearch(query, aes_key):
    '''Returns results of search.'''
    conn = sqlite3.connect(pwdatabase)
    result = showResult(conn.execute("select *,rowid from passwords where title like ?", ['%{}%'.format(query)]), aes_key)
    conn.close()
    return result

def showResult(result, aes_key):
    '''Renders given results.'''
    out = ''
    for row in result:
        out += html_results.format(headers=headers,title=row[0],url=row[1],username=row[2],password=decrypt(aes_key, row[3]).decode(),other=decrypt(aes_key, row[4]).decode(),rowid=row[5])
    return out

def mkPasswd():
    '''Returns generated password from pwgen command line utility.'''
    return subprocess.check_output(['pwgen','-cn','12','1']).decode().strip()

class Root(object):
    def index(self):
        out = ''
        if not loggedIn():
            out += html_login
        else:
            out += html_searchform + html_addform
        return html_template.format(content=out)
    index.exposed = True

    def genpass(self):
        return html_template.format(content=html_message.format(message=mkPasswd()))
    genpass.exposed = True

    def login(self, password=''):
        out = ''
        conn = sqlite3.connect(pwdatabase)
        master_pass = [i for i in conn.execute("select * from master_pass", ())]
        conn.close()
        pwHash = master_pass[0][0]
        salt = master_pass[0][1]
        if bcrypt.checkpw(password, pwHash):
            cookie = cherrypy.response.cookie
            cookie['auth'] = newKey()
            cookie['aes_key'] = toHex(bcrypt.kdf(password, salt, 16, 32))
            out += html_message.format(message='You are now logged in.') + html_searchform + html_addform
        else:
            failedLogin()
            out += html_message.format(message='Login failed.') + html_login
        return html_template.format(content=out)
    login.exposed = True

    def logout(self):
        out = ''
        cookie = cherrypy.request.cookie
        if 'auth' in cookie.keys():
            if delKey(cookie['auth'].value):
                out += html_message.format(message='You are now logged out.')
            else:
                out += html_message.format(message='Auth key not found.')
        else:
            out += html_message.format(message='You were not logged in.')
        return html_template.format(content=out)
    logout.exposed = True

    def search(self, query=''):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            out += pwSearch(query, aes_key) + html_searchform + html_addform
        return html_template.format(content=out)
    search.exposed = True

    def add(self, title, url='', username='', other=''):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            newrecord = ['' for i in range(5)]
            newrecord[0] = title
            newrecord[1] = url
            newrecord[2] = username
            newrecord[3] = password = mkPasswd()
            newrecord[4] = other
            out += html_results.format(headers=headers,title=title,url=url,username=username,password=password,other=other,rowid='')
            out += html_searchform + html_addform
            newrecord[3] = encrypt(aes_key, newrecord[3])
            newrecord[4] = encrypt(aes_key, newrecord[4])
            conn = sqlite3.connect(pwdatabase)
            conn.execute('insert into passwords values (?, ?, ?, ?, ?)', newrecord)
            conn.commit()
            conn.close()
        return html_template.format(content=out)
    add.exposed = True

    def delete(self, rowid, confirm=''):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            if confirm == 'true':
                conn = sqlite3.connect(pwdatabase)
                out += html_message.format(message="Record Deleted")
                out += showResult(conn.execute("select *,rowid from passwords where rowid=?", [rowid]), aes_key)
                conn.execute("delete from passwords where rowid=?", [rowid])
                conn.commit()
                conn.close()
            else:
                conn = sqlite3.connect(pwdatabase)
                out += html_message.format(message="Are you sure you want to delete this record?")
                out += showResult(conn.execute("select *,rowid from passwords where rowid=?", [rowid]), aes_key)
                out += html_confirmdelete.format(rowid=rowid)
                conn.close()
            out += html_searchform + html_addform
        return html_template.format(content=out)
    delete.exposed = True

    def edit(self, rowid, confirm='', title='', url='', username='', password='', other=''):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            if confirm == 'true':
                conn = sqlite3.connect(pwdatabase)
                conn.execute("update passwords set title=?, url=?, username=?, password=?, other=? where rowid=?", (title, url, username, encrypt(aes_key, password), encrypt(aes_key, other), rowid))
                conn.commit()
                record = conn.execute("select *,rowid from passwords where rowid=?", (rowid,)).fetchone()
                conn.close()
                out += showResult((record,), aes_key)
            else:
                conn = sqlite3.connect(pwdatabase)
                record = conn.execute("select * from passwords where rowid=?", (rowid,)).fetchone()
                conn.close()
                out += html_editform.format(rowid=rowid, title=record[0], url=record[1], username=record[2], password=decrypt(aes_key, record[3]).decode(), other=decrypt(aes_key, record[4]).decode())
            out += html_searchform + html_addform
        return html_template.format(content=out)
    edit.exposed = True

if __name__ == "__main__":
    cherrypy.quickstart(Root(), '/', 'app.conf')
