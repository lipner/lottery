import requests
import sys
import base64
import argparse
import time
import urllib.parse
import lottery
import os

GUESS_FIELD = "guess"
NAME_FIELD = "name"
TIME_FIELD = "timestamp"
WINNING_NUMS_FIELD = "winning_numbers"
CERTIFICATION_MESSAGE = "%s is a winner!"

def certify(args):
    params = {  'guess_blob': args.guess_blob, 
                'guess_mac': args.guess_mac,
                'winnings_blob': args.winnings_blob,
                'winnings_mac': args.winnings_mac,
                }
    resp = requests.get("%s/certify" % (args.server_url,), params = params)
    print("Certification mac: \n\t%s" % (resp.text,))

def verify(args):
    params = {  'guess_blob': args.guess_blob, 
                'guess_mac': args.guess_mac }
    resp = requests.get("%s/verify" % (args.server_url,), params = params)
    print("Result:")
    print("\t", resp.text)

def sign(args):
    guess = {}
    guess[GUESS_FIELD] = [args.guess1, args.guess2, args.guess3,
                          args.guess4, args.guess5, args.guess6]
    guess[NAME_FIELD] = args.name
    guess[TIME_FIELD] = int(time.time())

    guess_b64 = base64.urlsafe_b64encode(urllib.parse.urlencode(guess).encode("latin1"))
    
    (payment_blob, payment_mac) = args.payment_token.split('.')
    params = {'guess_blob': guess_b64,
            'payment_blob': payment_blob,
            'payment_mac': payment_mac }

    resp = requests.get("%s/sign" % (args.server_url,), params = params)
    mac_b64 = resp.text
    print("Guess blob: \n\t%r" % (guess_b64.decode("latin1"),))
    print("Guess mac: \n\t%r" % (mac_b64,))
    
def make_payment_token(args):
    nonce = os.urandom(4)    
    mac = lottery.LotteryMAC(args.signing_key.encode("latin1")).tag(nonce)
    token = b"%s.%s" % (base64.urlsafe_b64encode(nonce), 
                        base64.urlsafe_b64encode(mac))
    #print("Payment token: \n\t%s" % (token.decode("latin1")))
    print(token.decode("latin1"))

def make_winnings_blob(args):
    winnings = {}
    winnings[WINNING_NUMS_FIELD] = [args.guess1, args.guess2, args.guess3,
                                    args.guess4, args.guess5, args.guess6]
    
    winnings_encoded = urllib.parse.urlencode(winnings).encode("latin1")
    mac = lottery.LotteryMAC(args.signing_key.encode("latin1")).tag(winnings_encoded)
    print("Winning numbers:",)
    print("\t%r" % winnings[WINNING_NUMS_FIELD])
    print("Winnings blob: \n\t%r" % base64.urlsafe_b64encode(winnings_encoded).decode("latin1"))
    print("Signature blob: \n\t%r" % base64.urlsafe_b64encode(mac).decode("latin1")) 
    
def am_i_a_winner(args):
    params = {'winner' : base64.urlsafe_b64encode(args.name.encode("latin1")), 
              'certification' : args.certification_mac}
    resp = requests.get("%s/verify-certification" % (args.server_url,), params = params)
    print("Result:")
    print("\t", resp.text)

def main(raw_args):
    parser = argparse.ArgumentParser(description='Lottery client', add_help=False)
    parser.add_argument('server_url', type=str, help="lottery server url")
    parser.add_argument('action', type=str, help="Action to perform",
                        choices = ['sign', 'verify', 'certify', 'verify-cert', 'make-payment-token', 'sign-winning-nums'],
                        )
    raw_args.pop(0)
    args = parser.parse_args(raw_args[:2])
 
    if args.action == 'sign':
        subparser = argparse.ArgumentParser(parents=[parser,])
        subparser.add_argument('name', type=str, help="The guesser's name")
        for i in range(6):
            subparser.add_argument('guess%d' % (i+1,), type=int)
        subparser.add_argument('payment_token', type=str, help="base64 payment blob")
        args = subparser.parse_args(raw_args)
        sign(args)
    elif args.action == 'verify':
        subparser = argparse.ArgumentParser(parents=[parser,])
        subparser.add_argument('guess_blob', type=str, help="base64 guess blob")
        subparser.add_argument('guess_mac', type=str, help="base64 guess mac")
        args = subparser.parse_args(raw_args)
        verify(args)
    elif args.action == 'certify':
        subparser = argparse.ArgumentParser(parents=[parser,])
        subparser.add_argument('guess_blob', type=str, help="base64 guess blob")
        subparser.add_argument('guess_mac', type=str, help="base64 guess mac")
        subparser.add_argument('winnings_blob', type=str, help="base64 winning numbers blob")
        subparser.add_argument('winnings_mac', type=str, help="base64 winning numbers mac")
        args = subparser.parse_args(raw_args)
        certify(args)
    elif args.action == 'verify-cert':
        subparser = argparse.ArgumentParser(parents=[parser,])
        subparser.add_argument('name', type=str, help="Winning guesser's name")
        subparser.add_argument('certification_mac', type=str, help="Certification mac")
        args = subparser.parse_args(raw_args)
        am_i_a_winner(args)
    elif args.action == 'sign-winning-nums':
        # ADMIN MODE
        subparser = argparse.ArgumentParser(parents=[parser,])
        subparser.add_argument('signing_key', type=str, help="Winning numbers signing key")
        for i in range(6):
            subparser.add_argument('guess%d' % (i+1,), type=int)
        args = subparser.parse_args(raw_args)
        make_winnings_blob(args)
    elif args.action == 'make-payment-token':
        # ADMIN MODE
        subparser = argparse.ArgumentParser(parents=[parser,])
        subparser.add_argument('signing_key', type=str, help="Payment token signing key")
        args = subparser.parse_args(raw_args)
        make_payment_token(args)

if __name__ == "__main__":
    main(list(sys.argv))
