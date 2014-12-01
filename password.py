#! /usr/bin/env python3

import sqlite3
import subprocess
import os
import bcrypt
import hashlib
from Crypto.Cipher import AES
import codecs
import json
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
keyExpTime = 60 * 15

html_template = '''\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Password Manager</title>

  <!-- Bootstrap -->
  <link href="/static/css/bootstrap.min.css" rel="stylesheet">

  <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
  <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
  <!--[if lt IE 9]>
  <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
  <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
  <![endif]-->
</head>
<body>

  <nav class="navbar navbar-inverse navbar-static-top" role="navigation">
    <div class="container">
      <div class="navbar-header">
        <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
          <span class="sr-only">Toggle navigation</span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
        </button>
        <a class="navbar-brand" href="#">Password Manager</a>
      </div>
      <div id="navbar" class="navbar-collapse collapse">
        <ul class="nav navbar-nav">
          <li><a href="/">Home</a></li>
          <li><a href="/logout">Logout</a></li>
          <li class="dropdown">
            <a class="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="false" href="#">
              <span class="glyphicon glyphicon-cog" aria-hidden="true"></span>
              <span class="caret"></span>
              <ul class="dropdown-menu" role="menu">
                <li><a href="/newuser">New User</a></li>
                <li class="divider"></li>
                <li><a href="/all">Show All Records</a></li>
                <li><a href="/import">Import</a></li>
                <li><a href="/export">Export</a></li>
                <li><a href="/changepw">Change Master Password</a></li>
                <li class="divider"></li>
                <li><a href="/genpass">Generate Password</a></li>
              </ul>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="container">
    {content}
  </div>

  <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>
  <!-- Include all compiled plugins (below), or include individual files as needed -->
  <script src="/static/js/bootstrap.min.js"></script>
</body>
</html>
'''

html_setupform = '''\
<div class="panel panel-default">
  <div class="panel-body">

    <form class="form-inline" role="form" name="setup" action="/setup" method="post">

      <div class="form-group">
        <label>Username</label>
        <input class="form-control" type="text" name="user" autofocus>
      </div>

      <div class="form-group">
        <label>Password</label>
        <input class="form-control" type="password" name="password">
      </div>

      <button type="submit" class="btn btn-default">Set Password</button>

    </form>

  </div>
</div>
'''

html_newuserform = '''\
<div class="panel panel-default">
  <div class="panel-body">

    <form class="form-inline" role="form" name="newuser" action="/newuser" method="post">

      <div class="form-group">
        <label>Username</label>
        <input class="form-control" type="text" name="user" autofocus>
      </div>

      <div class="form-group">
        <label>Password</label>
        <input class="form-control" type="password" name="password">
      </div>

      <button type="submit" class="btn btn-default">Set Password</button>

    </form>

  </div>
</div>
'''

html_importform = '''\
<div class="panel panel-default">
  <div class="panel-body">

    <form role="form" name="import" action="/import" method="post">

      <div class="form-group">
        <textarea class="form-control" name="json"></textarea>
      </div>

      <button type="submit" class="btn btn-default">Import</button>

    </form>

  </div>
</div>
'''

html_searchform = '''\
<div class="panel panel-default">
  <div class="panel-body">

    <form class="form-inline" role="form" name="search" action="/search" method="get">

      <div class="form-group">
        <input class="form-control" type="text" name="query" autofocus>
      </div>

      <button type="submit" class="btn btn-default">Search</button>

    </form>

  </div>
</div>
'''

html_addform = '''\
<div class="panel panel-default">
  <div class="panel-heading">Add Record</div>
  <div class="panel-body">

    <form class="form-horizontal" role="form" name="add" action="/add" method="post">

      <div class="form-group">
        <label class="col-sm-3 control-label">Title:</label>
        <div class="col-sm-9">
          <input class="form-control" type="text" name="title">
        </div>
      </div>

      <div class="form-group">
        <label class="col-sm-3 control-label">URL:</label>
        <div class="col-sm-9">
          <input class="form-control" type="text" name="url">
        </div>
      </div>

      <div class="form-group">
        <label class="col-sm-3 control-label">Username:</label>
        <div class="col-sm-9">
          <input class="form-control" type="text" name="username">
        </div>
      </div>

      <div class="form-group">
        <label class="col-sm-3 control-label">Other:</label>
        <div class="col-sm-9">
          <textarea class="form-control" name="other"></textarea>
        </div>
      </div>

      <button type="submit" class="btn btn-default">Add</button>

    </form>

  </div>
</div>
'''

html_editform = '''\
<div class="panel panel-default">
  <div class="panel-heading">Edit Record</div>
  <div class="panel-body">

    <form class="form-horizontal" role="form" name="edit" action="/edit" method="post">

      <input type="hidden" name="rowid" value="{rowid}">
      <input type="hidden" name="confirm" value="true">

      <div class="form-group">
        <label class="col-sm-3 control-label">Title:</label>
        <div class="col-sm-9">
          <input class="form-control" type="text" name="title" value="{title}">
        </div>
      </div>

      <div class="form-group">
        <label class="col-sm-3 control-label">URL:</label>
        <div class="col-sm-9">
          <input class="form-control" type="text" name="url" value="{url}">
        </div>
      </div>

      <div class="form-group">
        <label class="col-sm-3 control-label">Username:</label>
        <div class="col-sm-9">
          <input class="form-control" type="text" name="username" value="{username}">
        </div>
      </div>

      <div class="form-group">
        <label class="col-sm-3 control-label">Password:</label>
        <div class="col-sm-9">
          <input class="form-control" type="text" name="password" value="{password}">
        </div>
      </div>

      <div class="form-group">
        <label class="col-sm-3 control-label">Other:</label>
        <div class="col-sm-9">
          <textarea class="form-control" name="other">{other}</textarea>
        </div>
      </div>

      <button type="submit" class="btn btn-default">Submit</button>

    </form>

  </div>
</div>
'''

html_results = """\
<div class="panel panel-default">
  <div class="panel-body">
    <div class="row">
      <div class="col-sm-3"><strong>{headers[0]}</strong></div>
      <div class="col-sm-9">{title}</div>
    </div>
    <div class="row">
      <div class="col-sm-3"><strong>{headers[1]}</strong></div>
      <div class="col-sm-9"><a target="_blank" href="{url}">{url}</a></div>
    </div>
    <div class="row">
      <div class="col-sm-3"><strong>{headers[2]}</strong></div>
      <div class="col-sm-9">{username}</div>
    </div>
    <div class="row">
      <div class="col-sm-3"><strong>{headers[3]}</strong></div>
      <div class="col-sm-9"><samp>{password}</samp></div>
    </div>
    <div class="row">
      <div class="col-sm-3"><strong>{headers[4]}</strong></div>
      <div class="col-sm-9"><pre>{other}</pre></div>
    </div>
  </div>
  <div class="panel-footer">
    <a href="/delete?rowid={rowid}"><span class="glyphicon glyphicon-trash" aria-hidden="true"></span></a>
    <span style="display:inline-block;width:1em;" aria-hidden="true"></span>
    <a href="/edit?rowid={rowid}"><span class="glyphicon glyphicon-pencil" aria-hidden="true"></span></a>
  </div>
</div>
"""

html_message = """\
<div class="alert alert-info" role="alert">{message}</div>
"""

html_confirmdelete = '''\
<div class="panel panel-default">
  <div class="panel-body">

    <form class="form-inline" role="form" name="confirmdelete" action="/delete" method="post">

      <input type="hidden" name="rowid" value="{rowid}">
      <input type="hidden" name="confirm" value="true">

      <button type="submit" class="btn btn-warning">Confirm Delete</button>

    </form>

  </div>
</div>
'''

html_changemasterpassform = '''\
<div class="panel panel-default">
  <div class="panel-body">

    <form class="form-inline" role="form" name="changepw" action="/changepw" method="post">

      <div class="form-group">
        <label>Password</label>
        <input class="form-control" type="password" name="password" autofocus>
      </div>

      <button type="submit" class="btn btn-default">Change Password</button>

    </form>

  </div>
</div>
'''

html_login = '''\
<div class="panel panel-default">
  <div class="panel-body">

    <form class="form-inline" role="form" name="login" action="/login" method="post">

      <div class="form-group">
        <label>Username</label>
        <input class="form-control" type="text" name="user" autofocus>
      </div>

      <div class="form-group">
        <label>Password</label>
        <input class="form-control" type="password" name="password">
      </div>

      <button type="submit" class="btn btn-default">Login</button>

    </form>

  </div>
</div>
'''

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

def newKey(user):
    '''Creates new key, adds it to database with timestamp, and returns it.'''
    key = genHex()
    date = nowUnixInt()
    authKeys[key] = (user, date)
    return key

def delKey(key):
    '''Removes auth key. Used for logout.'''
    if key in authKeys:
        del authKeys[key]
        return True
    return False

def keyUser(key):
    '''Return appuser for given key.'''
    if key in authKeys:
        return authKeys[key][0]

def keyValid(key):
    '''Return True if key is in database and is not expired. Updates timestamp if key is valid.'''
    now = nowUnixInt()
    exp_date = now - keyExpTime
    keys = [key for key in authKeys.keys()]
    for i in keys:
        if authKeys[i][1] < exp_date:
          del authKeys[i]
    if key not in authKeys:
        return False
    authKeys[key] = (keyUser(key), now)
    return True

def pwSearch(query, appuser, aes_key):
    '''Returns results of search.'''
    conn = sqlite3.connect(pwdatabase)
    result = showResult(conn.execute('select *,rowid from passwords where appuser=? and passwords match ?', (appuser, query)), aes_key)
    conn.close()
    return result

def getById(rowid, appuser, aes_key):
    '''Returns single record by rowid.'''
    conn = sqlite3.connect(pwdatabase)
    result = showResult(conn.execute('select *,rowid from passwords where rowid=? and appuser=?', (rowid, appuser)), aes_key)
    conn.close()
    return result

def getValuesById(rowid, appuser, aes_key):
    '''Returns record values by rowid.'''
    conn = sqlite3.connect(pwdatabase)
    record = conn.execute('select *,rowid from passwords where rowid=? and appuser=?', (rowid, appuser)).fetchone()
    conn.close()
    record = list(record)
    record[3] = decrypt(aes_key, record[3]).decode()
    record[4] = decrypt(aes_key, record[4]).decode()
    return record

def getAll(appuser, aes_key):
    '''Return all records for appuser'''
    conn = sqlite3.connect(pwdatabase)
    result = showResult(conn.execute('select *,rowid from passwords where appuser=?', (appuser,)), aes_key)
    conn.close()
    return result

def getAllValues(appuser, aes_key):
    '''Returns all records values for appuser.'''
    conn = sqlite3.connect(pwdatabase)
    records = [list(i) for i in conn.execute('select title, url, username, password, other from passwords where appuser=?', (appuser,))]
    conn.close()
    for i in range(len(records)):
        records[i][3] = decrypt(aes_key, records[i][3]).decode()
        records[i][4] = decrypt(aes_key, records[i][4]).decode()
    return records

def deleteById(rowid, appuser):
    '''Deletes record by rowid.'''
    conn = sqlite3.connect(pwdatabase)
    conn.execute('delete from passwords where rowid=? and appuser=?', (rowid, appuser))
    conn.commit()
    conn.close()

def updateById(rowid, appuser, aes_key, record):
    '''Updates a record.'''
    title, url, username, password, other = record
    password = encrypt(aes_key, password)
    other = encrypt(aes_key, other)
    conn = sqlite3.connect(pwdatabase)
    conn.execute('update passwords set title=?, url=?, username=?, password=?, other=? where rowid=? and appuser=?', (title, url, username, password, other, rowid, appuser))
    conn.commit()
    conn.close()

def changeMasterPass(appuser, aes_key, newPass):
    '''Change users master password. '''
    newPWHash = bcrypt.hashpw(newPass, bcrypt.gensalt())
    newSalt = os.urandom(16)
    new_aes_key = bcrypt.kdf(newPass, newSalt, 16, 32)
    conn = sqlite3.connect(pwdatabase)
    rowids = [i[0] for i in conn.execute('select rowid from passwords where appuser=?', (appuser,)).fetchall()]
    for rowid in rowids:
        password, other = conn.execute('select password, other from passwords where rowid=?', (rowid,)).fetchone()
        password = encrypt(new_aes_key, decrypt(aes_key, password))
        other = encrypt(new_aes_key, decrypt(aes_key, other))
        conn.execute('update passwords set password=?, other=? where rowid=?', (password, other, rowid))
    conn.execute('update master_pass set password=?, salt=? where appuser=?', (newPWHash, newSalt, appuser))
    conn.commit()
    conn.close()

def showResult(result, aes_key):
    '''Renders given results.'''
    out = ''
    for row in result:
        out += html_results.format(headers=headers,title=row[0],url=row[1],username=row[2],password=decrypt(aes_key, row[3]).decode(),other=decrypt(aes_key, row[4]).decode(),rowid=row[6])
    return out

def mkPasswd():
    '''Returns generated password from pwgen command line utility.'''
    return subprocess.check_output(['pwgen','-cn','12','1']).decode().strip()

def importJson(appuser, aes_key, json_data):
    records = json.loads(json_data)
    conn = sqlite3.connect(pwdatabase)
    for record in records:
        title, url, username, password, other = record
        password = encrypt(aes_key, password)
        other = encrypt(aes_key, other)
        conn.execute('insert into passwords values (?, ?, ?, ?, ?, ?)', (title, url, username, password, other, appuser))
    conn.commit()
    conn.close()

def existsAppUser(user):
    conn = sqlite3.connect(pwdatabase)
    existing_user = conn.execute('select appuser from master_pass where appuser=?', (user,)).fetchall()
    conn.close()
    if len(existing_user) > 0:
        return True
    else:
        return False

def newAppUser(user, password):
    pwHash = bcrypt.hashpw(password, bcrypt.gensalt())
    conn = sqlite3.connect(pwdatabase)
    conn.execute('insert into master_pass values (?, ?, ?)', (user, pwHash, os.urandom(16)))
    conn.commit()
    conn.close()

def newDB(user, password):
    conn = sqlite3.connect(pwdatabase)
    conn.execute('create virtual table passwords using fts4(title, url, username, password, other, appuser, notindexed=password, notindexed=other, notindexed=appuser)')
    conn.execute('create table master_pass (appuser text primary key not null, password text, salt text)')
    conn.commit()
    conn.close()
    newAppUser(user, password)

class Root(object):
    def index(self):
        out = ''
        if not os.path.isfile(pwdatabase):
            raise cherrypy.HTTPRedirect('/setup')
        if not loggedIn():
            out += html_login
        else:
            out += html_searchform + html_addform
        return html_template.format(content=out)
    index.exposed = True

    def setup(self, user='', password=''):
        out = ''
        if os.path.isfile(pwdatabase):
            out += html_message.format(message='Database file already exists.')
            return html_template.format(content=out)
        if (not password) or (not user):
            out += html_message.format(message='No database file found. Setting up new database.')
            out += html_setupform
            return html_template.format(content=out)
        else:
            newDB(user, password)
            out += html_message.format(message='New database has been created.')
            out += html_login
            return html_template.format(content=out)
    setup.exposed = True

    def newuser(self, user='', password=''):
        out = ''
        if (not password) or (not user):
            out += html_message.format(message='Create a new user.')
            out += html_newuserform
        elif existsAppUser(user):
            out += html_message.format(message='That user already exists.')
            out += html_newuserform
        else:
            newAppUser(user, password)
            out += html_message.format(message='New user has been created.')
            out += html_login
        return html_template.format(content=out)
    newuser.exposed = True

    def genpass(self):
        return html_template.format(content=html_message.format(message=mkPasswd()))
    genpass.exposed = True

    def login(self, user='', password=''):
        out = ''
        conn = sqlite3.connect(pwdatabase)
        master_pass = conn.execute('select * from master_pass where appuser=?', (user,)).fetchone()
        conn.close()
        pwHash = master_pass[1]
        salt = master_pass[2]
        if bcrypt.checkpw(password, pwHash):
            cookie = cherrypy.response.cookie
            cookie['auth'] = newKey(user)
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
        out += html_login
        return html_template.format(content=out)
    logout.exposed = True

    @cherrypy.expose('all')
    def all_records(self):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            appuser = keyUser(cherrypy.request.cookie['auth'].value)
            out += getAll(appuser, aes_key)
        return html_template.format(content=out)

    def search(self, query=''):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            appuser = keyUser(cherrypy.request.cookie['auth'].value)
            out += html_searchform + pwSearch(query, appuser, aes_key)
        return html_template.format(content=out)
    search.exposed = True

    def add(self, title, url='', username='', other=''):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            appuser = keyUser(cherrypy.request.cookie['auth'].value)
            password = encrypt(aes_key, mkPasswd())
            other = encrypt(aes_key, other)
            newrecord = (title, url, username, password, other, appuser)
            conn = sqlite3.connect(pwdatabase)
            cur = conn.cursor()
            cur.execute('insert into passwords values (?, ?, ?, ?, ?, ?)', newrecord)
            rowid = cur.lastrowid
            conn.commit()
            out += html_message.format(message='Record added.')
            out += getById(rowid, appuser, aes_key)
            conn.close()
            out += html_searchform
        return html_template.format(content=out)
    add.exposed = True

    def delete(self, rowid, confirm=''):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            appuser = keyUser(cherrypy.request.cookie['auth'].value)
            if confirm == 'true':
                out += html_message.format(message="Record deleted.")
                out += getById(rowid, appuser, aes_key)
                deleteById(rowid, appuser)
            else:
                out += html_message.format(message="Are you sure you want to delete this record?")
                out += getById(rowid, appuser, aes_key)
                out += html_confirmdelete.format(rowid=rowid)
        return html_template.format(content=out)
    delete.exposed = True

    def edit(self, rowid, confirm='', title='', url='', username='', password='', other=''):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            appuser = keyUser(cherrypy.request.cookie['auth'].value)
            if confirm == 'true':
                record = (title, url, username, password, other)
                updateById(rowid, appuser, aes_key, record)
                out += html_message.format(message='Record updated.')
                out += getById(rowid, appuser, aes_key)
            else:
                record = getValuesById(rowid, appuser, aes_key)
                out += html_editform.format(rowid=rowid, title=record[0], url=record[1], username=record[2], password=record[3], other=record[4])
        return html_template.format(content=out)
    edit.exposed = True

    @cherrypy.expose()
    def changepw(self, password=''):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        elif not password:
            out += html_message.format(message='Change your master password. You may want to export your data first, just in case.')
            out += html_changemasterpassform
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            auth = cherrypy.request.cookie['auth'].value
            appuser = keyUser(auth)
            changeMasterPass(appuser, aes_key, password)
            delKey(auth)
            out += html_message.format(message='Your master password has been changed. Please log back in.')
            out += html_login
        return html_template.format(content=out)

    @cherrypy.expose('import')
    def import_json(self, json=''):
        out = ''
        if not loggedIn():
            out += html_message.format(message='You are not logged in.') + html_login
        elif not json:
            out += html_message.format(message='Enter json data to import.')
            out += html_importform
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            appuser = keyUser(cherrypy.request.cookie['auth'].value)
            importJson(appuser, aes_key, json)
            out += html_message.format(message='Json data imported.')
        return html_template.format(content=out)

    @cherrypy.expose()
    def export(self):
        if not loggedIn():
            out = html_message.format(message='You are not logged in.') + html_login
            return html_template.format(content=out)
        else:
            aes_key = fromHex(cherrypy.request.cookie['aes_key'].value)
            appuser = keyUser(cherrypy.request.cookie['auth'].value)
            return json.dumps(getAllValues(appuser, aes_key), indent=2)

if __name__ == "__main__":
    cherrypy.quickstart(Root(), '/', 'app.conf')
