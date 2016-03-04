#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2

import string, re
from google.appengine.ext import db
import hmac

USER_re=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_re=re.compile(r"^.{3,20}$")
EMAIL_re=re.compile(r"^[\S]+@[\S]+\.[\S]+$")

months= ['January','February', 'March']

def valid_username(username):
    if USER_re.match(username) and username:
        return True
    else:
        return False

def valid_pass(password):
    if PASS_re.match(password) and password:
        return True
    else:
        return False

def valid_email(email):
    if EMAIL_re.match(email) or email=='':
        return True
    else:
        return False


def valid_month(month):
    for mon in months:
        if string.upper(month)==string.upper (mon):return mon
        
def valid_day(day):
    try:
        inDay=int(day)
        if (inDay>0)&(inDay<32):
            return inDay
        else:
            return None
    except:
        return None
    
def valid_year(year):
    try:
        intYear=int(year)
        if (intYear>1900)&(intYear<2020):
            return intYear
        else:
            return None
    except:
        return None

def escape_html(s):
    out_s=s.replace('&','&amp;')
    out_s=out_s.replace('>','&gt;')
    out_s=out_s.replace('<','&lt;')
    out_s=out_s.replace('"','&quot;')
    return out_s

def rot13(s):
    letter_string='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    orig_string=s
    result_string=''
    find_mark=0
    for i in range(len(orig_string)):
        find_mark=0
        for j in range(52):
            if orig_string[i]==letter_string[j]:
                find_mark=1
                if j<13:
                    result_string=result_string+letter_string[j+13]
                elif j<26:
                    result_string=result_string+letter_string[j-13]
                elif j<39:
                    result_string=result_string+letter_string[j+13]
                else:
                    result_string=result_string+letter_string[j-13]

        if find_mark==0:result_string=result_string+orig_string[i]
                

    return result_string
        
form="""
<form method="post">
    What is your birthday?
    <br>
    <label>
        Day
        <input type="text" name="day" value="%(day)s">
    </label>
    <label>
        Month
        <input type="text" name="month" value="%(month)s">
    </label>
    <label>
        Year
        <input type="text" name="year" value="%(year)s">
    </label>
    <div style="color:red">%(error)s<div>
    <br>
    <br>
    <input type="submit">
</form>
"""

form2="""
<form method="post">
    Rot13 test page
    <br>
    <br>
    <textarea name="text" cols="50" rows="10">%(text)s</textarea>
    <br>
    <br>
    <input type="submit">
</form>
"""

signup_form="""
<form method="post">
    Sign Up
    <br>
    <br>
    <label>
        Username
        <input type="text" name="username" value="%(username)s">
        <span style="color:red">%(un_error)s</span>
    </label>
    <br>
    <label>
        Password
        <input type="text" name="password">
        <span style="color:red">%(pass_error)s</span>
    </label>
    <br>
    <label>
        Confirm password
        <input type="text" name="verify" >
        <span style="color:red">%(verify_error)s</span>
    </label>
    <br>
    <label>
        Email (optional)
        <input type="text" name="email" value="%(email)s">
        <span style="color:red">%(email_error)s</span>
    </label>
    <br>
    <br>
    <input type="submit">
</form>
"""
login_form="""
<form method="post">
    Sign Up
    <br>
    <br>
    <label>
        Username
        <input type="text" name="username" value="%(username)s">
        
    </label>
    <br>
    <label>
        Password
        <input type="text" name="password">
        <div style="color:red">%(login_error)s</div>
    </label>
    <br>
    <br>
    <input type="submit">
</form>
"""

class MainHandler(webapp2.RequestHandler):
    def write_form(self, error="", day="", month="", year=""):
        self.response.out.write(form % {"error": error,
                                        "day": escape_html(day),
                                        "month": escape_html(month),
                                        "year": escape_html(year)})
    def get(self):
        self.write_form()
    def post(self):
        user_day=self.request.get('day')
        user_month=self.request.get('month')
        user_year=self.request.get('year')

        day=valid_day(user_day)
        month=valid_month(user_month)
        year=valid_year(user_year)
        
        if not(day and month and year):
            self.write_form("Input data seemed to be invalid!", user_day, user_month, user_year)
        else:
 
            self.redirect('/thanks')

class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write('Thank you!')

class unit2Handler(webapp2.RequestHandler):
    def write_form(self, rot13_text=""):
        self.response.out.write(form2 % {"text":escape_html(rot13_text)})
    
    def get(self):
        self.write_form()

    def post(self):
        user_text=self.request.get('text')
        self.write_form(rot13(user_text))

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)

class SignupHandler(webapp2.RequestHandler):
    def write_form(self, username="", email="", un_error="", pass_error="", verify_error="", email_error=""):
        self.response.out.write(signup_form % {"username": username,
                                               "email": email,
                                               "un_error": un_error,
                                               "pass_error": pass_error,
                                               "verify_error": verify_error,
                                               "email_error": email_error})
        
    def get(self):
        self.write_form()

    def post(self):
        user_username=self.request.get('username')
        user_pass=self.request.get('password')
        user_verify=self.request.get('verify')
        user_email=self.request.get('email')

        result=True
        un_error=''
        pass_error=''
        verify_error=''
        email_error=''

        if valid_username(user_username):
            if not(User.gql('WHERE username = :name', name = user_username).get()):
                result = result and True
            else:
                un_error = 'User already exists'
                result = result and False
        else:
            un_error = 'Username is not valid'
            result = result and False
            
        if valid_pass(user_pass):
            if user_pass == user_verify:
                result = result and True
            else:
                verify_error = "Password doesn't match"
                result = result and False
        else:
            pass_error='Password is not valid'
            result = result and False
        
        if valid_email(user_email):
            result = result and True
        else:
            email_error = 'Email is not valid'
            result = result and False

##        self.response.out.write(User.gql('WHERE username = :name', name = user_username).get())
##        self.response.out.write(None)
        
        if result :
            hash_password = hmac.new('secret',user_pass).hexdigest()
            user = User(username=user_username, password=hash_password)
            user.put()
            cookie_string = str(user.key().id())+'|'+hash_password
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % cookie_string)
            self.redirect('/welcome')
        else:
            self.write_form(user_username,user_email,un_error,pass_error,verify_error,email_error)

class LoginHandler(webapp2.RequestHandler):
    def write_form(self, username="", login_error=""):
        self.response.out.write(login_form % {"username": username,
                                               "login_error": login_error})
    def get(self):
        self.write_form()

    def post(self):
        user_name=self.request.get('username')
        user_pass=self.request.get('password')
        login_user=User.gql('WHERE username = :name', name = user_name).get()
        if login_user:
            db_un_pass=login_user.password
            entered_pass_hash=hmac.new('secret',user_pass).hexdigest()
            if db_un_pass==entered_pass_hash:
                cookie_string = str(login_user.key().id())+'|'+str(db_un_pass)
##                self.response.out.write(cookie_string)
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % cookie_string)
                self.redirect('/welcome')
            else:
                self.write_form(user_name, 'Login error - invalid password')
        else:
            self.write_form(user_name, 'Login error - invalid user')
        
class LogoutHandler(webapp2.RequestHandler):
    def get(self):
        self.response.delete_cookie('user_id')
##        self.response.out.write('clear')
        self.redirect('/unit2/signup')

class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        if not(self.request.cookies.get('user_id')):
            self.redirect('unit2/signup')
        else:
            cookie = self.request.cookies.get('user_id').split('|')
            key = db.Key.from_path('User', int(cookie[0]))
            curr_user = db.get(key)
            if curr_user.password==cookie[1]:
                self.response.out.write('Welcome, '+curr_user.username+'!')
            else:
                self.redirect('unit2/signup')
        
##        self.response.out.write(curr_user.password)    

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/thanks', ThanksHandler),
    ('/unit2', unit2Handler),
    ('/unit2/signup', SignupHandler),
    ('/welcome', WelcomeHandler),
    ('/unit2/login', LoginHandler),
    ('/unit2/logout', LogoutHandler)
   
], debug=True)
