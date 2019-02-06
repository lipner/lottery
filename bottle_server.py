#!/usr/local/bin/python
from bottle import Bottle, route, get, request, static_file
import argparse
import binascii
import time
import base64

import lottery

app = Bottle()

@app.get('/winning-blob')
def winning_blob_static():
    # After numbers have been drawn, the winning blob and mac will be served from 
    # this path
    return static_file('winning.blob','/tmp')

@app.route('/')
def welcome():
    msg = "Welcome to the lottery server!" + "\n"
    msg += "Our state-of-the-art stateless lottery implementation can be found " 
    msg += "<a href=\"https://github.com/h1ghr0llerz/lottery\">here</a>." + "\n"
    return msg

@app.route('/time-left')
def time_left():
    left = lottery_inst._cutoff_time - int(time.time())
    if left > 0:
        return str(lottery_inst._cutoff_time - int(time.time()))
    else:
        return "Time's up!"

@app.route('/verify-certification')
def verify_winner_certification():
    winner_name_b64 = request.query.winner.encode("utf-8")
    certification_mac_b64 = request.query.certification.encode("utf-8")
    
    if not winner_name_b64 or not certification_mac_b64:
        return "Please submit the winner's name and a valid winner certification"
    
    try:
        winner_name = base64.urlsafe_b64decode(winner_name_b64).decode("latin1")
        certification_mac = base64.urlsafe_b64decode(certification_mac_b64)
    except binascii.Error:
        return "Base64 decode error"
    if lottery_inst.verify_winner_certification(winner_name, certification_mac):
        return "You are a winner"
    else:
        return "You are not a winner :("


@app.route('/certify')
def certify_guess():
    guess_blob_b64 = request.query.guess_blob.encode("utf-8")
    guess_mac_b64 = request.query.guess_mac.encode("utf-8")
    winnings_blob_b64 = request.query.winnings_blob.encode("utf-8")
    winnings_mac_b64 = request.query.winnings_mac.encode("utf-8")
    
    if not all((guess_blob_b64, guess_mac_b64, 
                winnings_blob_b64, winnings_mac_b64, 
    )):
        return "Please submit your guess, the winning numbers (signed)"
    
    try:
        guess_blob = base64.urlsafe_b64decode(guess_blob_b64)
        guess_mac = base64.urlsafe_b64decode(guess_mac_b64)
        winnings_blob = base64.urlsafe_b64decode(winnings_blob_b64)
        winnings_mac = base64.urlsafe_b64decode(winnings_mac_b64)
    except binascii.Error:
        return "Base64 decode error"
    
    try:
        result = lottery_inst.certify_winning_guess(
                guess_blob, guess_mac,
                winnings_blob, winnings_mac, 
            )
        if result:
            return base64.urlsafe_b64encode(result)
    except lottery.LotteryException as e:
        return str(e)

@app.route('/sign')
def sign_guess():
    guess_blob_b64 = request.query.guess_blob.encode("utf-8")
    payment_blob_b64 = request.query.payment_blob.encode("utf-8")
    payment_mac_b64 = request.query.payment_mac.encode("utf-8")
    if not all((payment_blob_b64, payment_mac_b64, guess_blob_b64)):
        return "Please submit a guess blob, and a payment token"

    try:
        guess_blob = base64.urlsafe_b64decode(guess_blob_b64)
        payment_blob = base64.urlsafe_b64decode(payment_blob_b64)
        payment_mac = base64.urlsafe_b64decode(payment_mac_b64)
    except binascii.Error:
        return "Base64 decode error"

    try:
        result = lottery_inst.sign_guess_blob(guess_blob, payment_blob, payment_mac) 
        if result:
            return base64.urlsafe_b64encode(result)
    except lottery.LotteryException as e:
        return str(e)

@app.route('/verify')
def verify_guess():
    guess_blob_b64 = request.query.guess_blob.encode("utf-8")
    guess_mac_b64 = request.query.guess_mac.encode("utf-8")
    if not guess_blob_b64 or not guess_mac_b64:
        return "Please submit a guess blob and a mac blob"
    try:
        guess_blob = base64.urlsafe_b64decode(guess_blob_b64)
        mac_blob = base64.urlsafe_b64decode(guess_mac_b64)
    except binascii.Error:
        return "Base64 decode error"

    try:
        result = lottery_inst.verify_guess_blob(guess_blob, mac_blob) 
        if result:
            return "Verified"
        else:
            return "Not verified"
    except lottery.LotteryException as e:
        return str(e)
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Lottery server arguments')
    parser.add_argument('--signing_key', type=str, help='Signing key for guesses', required=True)
    parser.add_argument('--winning_key', type=str, help='Winning key for winning numbers', required=True)
    parser.add_argument('--certification_key', type=str, help='Certification key for winner certification', required=True)
    parser.add_argument('--payment_key', type=str, help='Payment key for payment tokens', required=True)
    parser.add_argument('--duration', type=int, help='Duration in seconds of the lottery session', required=True)
    args = parser.parse_args()

    lottery_inst = lottery.Lottery(
                args.signing_key.encode("latin1"), 
                args.winning_key.encode("latin1"), 
                args.certification_key.encode("latin1"), 
                args.payment_key.encode("latin1"), 
                int(time.time()) + args.duration)

    app.run(host='0.0.0.0', debug=True)
