#! /usr/bin/env python3

from splinter import Browser

with Browser() as browser:
    url = 'https://pw.djones.co'
    browser.visit(url)
    browser.fill('user', 'test')
    browser.fill('password', '1234')
    button = browser.find_by_id('login')
    button.click()
    if browser.is_text_present('You are now logged in.'):
        print('Logged in.')
    else:
        print('Login failed.')
    browser.visit(url)
    if browser.is_text_present('Add Record'):
        print('Still logged in.')
    else:
        print('Failed: Not logged in anymore.')
    browser.visit(url + '/logout')
    browser.visit(url)
    if browser.is_text_not_present('Add Record'):
        print('Logout success.')
    else:
        print('Failed.')
