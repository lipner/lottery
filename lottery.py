from Crypto.Hash import SHA
import redis
import urllib.parse
import json
import time

class LotteryMAC(object):
    def __init__(self, key):
        self._key = key 

    def tag(self, message):
        return SHA.new(self._key + message).digest()
    
    def verify(self, message, tag):
        return tag == self.tag(message)

class LotteryException(Exception):
    pass

class PaymentVerifierPersistentRedis(object):
    def __init__(self, key, redis_instance):
        self._key = key

        self._redis = redis_instance

    def validate(self, blob, mac):
        if not self._redis.exists(blob):
            return LotteryMAC(self._key).verify(blob, mac)
        return False
    
    def consume(self, blob, mac):
        if self.validate(blob, mac):
            self._redis.set(blob, "1")
            return True
        return False

class Lottery(object):
    GUESS_FIELD = "guess"
    NAME_FIELD = "name"
    TIME_FIELD = "timestamp"
    WINNING_NUMS_FIELD = "winning_numbers"
    CERTIFICATION_MESSAGE = "%s is a winner!"
    PAYMENT_BLOB_KEY_LENGTH = 4
    def __init__(self, signing_key, winning_key, certification_key, payment_key, cutoff_time):
        """Initializes a Lottery object. The signing key is used to sign guess blobs for participants.
        The winning_key is the key with which the winning numbers are provided (after the cutoff time).
        The certification key is the key with which the winners are certified, subject to submission of 
        valid winning numbers (signed with the signing key) and a matching guess blob (signed with the signing key).
        The cutoff time is the point after which no more blobs are signed."""
        self._signing_key = signing_key
        self._winning_key = winning_key
        self._certification_key = certification_key

        self._payment_verifier = PaymentVerifierPersistentRedis(payment_key, redis.Redis(host='redis', port=6379))

        self._cutoff_time = cutoff_time
        if not self._is_before_cutoff(self._current_time()):
            raise LotteryException("Cutoff time has already passed.")

    def _current_time(self):
        # TODO - implement NTP
        return int(time.time())
    
    def _is_before_cutoff(self, time):
        return time < self._cutoff_time
    
    def _check_guess_format(self, guess):
        """Takes a guess (in dict format) and verifies the parameters"""
        # Guess field is a list of integers
        if self.GUESS_FIELD not in guess:
            raise LotteryException("Missing guess parameter.")
        if (type(guess[self.GUESS_FIELD]) is not list or
            not all(type(_) is int for _ in guess[self.GUESS_FIELD])):
            raise LotteryException("Wrong guess format.")        
       
        # Name field is a string 
        if self.NAME_FIELD not in guess:
            raise LotteryException("Missing name parameter.")
        if type(guess[self.NAME_FIELD]) is not str:
            raise LotteryException("Wrong name format.")
       
        # Timestamp field is epoch time (integer) 
        if self.TIME_FIELD not in guess:
            raise LotteryException("Missing timestamp parameter.")   
        if type(guess[self.TIME_FIELD]) is not int:
            raise LotteryException("Wrong timestamp format.")

    def _consume_payment_token(self, blob, mac):
        assert type(blob) is bytes
        assert type(mac) is bytes
        return self._payment_verifier.consume(blob, mac)

    def sign_guess_blob(self, blob, payment_blob, payment_mac):
        """Takes a json blob of data and signs it. The blob has to be in valid guess format. 
        Blobs cannot be signed after the cutoff time has passed.
        Returns a MAC as a byte array"""
        assert type(blob) is bytes
        assert type(payment_blob) is bytes
        assert type(payment_mac) is bytes

        if not self._is_before_cutoff(self._current_time()):
            raise LotteryException("Cutoff time has passed, no longer signing guesses.")

        try:
            # Parse blob into dict
            guess = dict(urllib.parse.parse_qsl(blob.decode("latin1")))
            guess[self.GUESS_FIELD] = json.loads(guess[self.GUESS_FIELD])
            guess[self.TIME_FIELD] = int(guess[self.TIME_FIELD])
        except (json.decoder.JSONDecodeError, KeyError, ValueError):
            raise LotteryException("Guess decode error, guess not accepted.")
        assert type(guess) is dict
        self._check_guess_format(guess) # Raises an exception if not valid

        if not self._is_before_cutoff(guess[self.TIME_FIELD]):
            raise LotteryException("Guess timestamp is after cutoff time, not signing.")
    
        # Try and consume payment token - if its invalid or already used, fail.
        if not self._consume_payment_token(payment_blob, payment_mac):
            raise LotteryException("Could not consume payment token.")

        return LotteryMAC(self._signing_key).tag(blob)

    def _verify_blob(self, blob, mac, key):
        assert type(blob) is bytes
        assert type(mac) is bytes
        assert type(key) is bytes
         
        return LotteryMAC(key).verify(blob, mac)

    def verify_guess_blob(self, blob, mac):
        """Takes a blob of data and a corresponding MAC and verifies that it is correct."""
        return self._verify_blob(blob, mac, self._signing_key)

    def verify_winnings_blob(self, blob, mac):
        return self._verify_blob(blob, mac, self._winning_key)
    
    def _check_winnings_format(self, winnings):
        # Winning numbers is a list of integers
        if self.WINNING_NUMS_FIELD not in winnings:
            raise LotteryException("Missing winning numbers field")
        if (type(winnings[self.WINNING_NUMS_FIELD]) is not list or
            not all(type(_) is int for _ in winnings[self.WINNING_NUMS_FIELD])):
            raise LotteryException("Wrong winning numbers format.") 

    def certify_winning_guess(self, 
            guess_blob, guess_mac, 
            winnings_blob, winnings_mac,
            ):
        """Takes a blob of winning numbers and their MAC and verifies them. Then verifies the guess blob
        using its MAC and checks if its a winner. If so, signs a message to certify the guessers name as a winner."""
        assert type(guess_blob) is bytes
        assert type(guess_mac) is bytes
        assert type(winnings_blob) is bytes
        assert type(winnings_mac) is bytes

        # Verify winning numbers mac
        if not self.verify_winnings_blob(winnings_blob, winnings_mac):
            raise LotteryException("Could not verify winning numbers.")
        # Verify guess mac
        if not self._verify_blob(guess_blob, guess_mac, self._signing_key):
            raise LotteryException("Could not verify guess blob.")

        # Parse guess and mac
        try:
            guess = dict(urllib.parse.parse_qsl(guess_blob.decode("latin1")))
            guess[self.GUESS_FIELD] = json.loads(guess[self.GUESS_FIELD])
            guess[self.TIME_FIELD] = int(guess[self.TIME_FIELD])

            winnings = dict(urllib.parse.parse_qsl(winnings_blob.decode("latin1")))
            winnings[self.WINNING_NUMS_FIELD] = json.loads(winnings[self.WINNING_NUMS_FIELD])
        except (json.decoder.JSONDecodeError, KeyError, ValueError):
            raise LotteryException("Certification decode error, not accepted.")

        assert type(guess) is dict
        self._check_guess_format(guess)
        assert type(winnings) is dict
        self._check_winnings_format(winnings)

        # Check guessed numbers (in any order?)
        if set(guess[self.GUESS_FIELD]) == set(winnings[self.WINNING_NUMS_FIELD]):
            # We have a winner!
            # Sign the certification message for the winning name.
            return LotteryMAC(self._certification_key).tag(
                    (self.CERTIFICATION_MESSAGE % (guess[self.NAME_FIELD],)).encode("latin1")
                )

        # Could not certify
        raise LotteryException("Could not certify, are the winning numbers correct?")        
        return None
        
    def verify_winner_certification(self, winner_name, certification_mac):
        return self._verify_blob(
                (self.CERTIFICATION_MESSAGE % (winner_name,)).encode("latin1"),
                certification_mac,
                self._certification_key
            )
            
        
        
