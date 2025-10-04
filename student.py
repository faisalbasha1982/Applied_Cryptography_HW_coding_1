#!/usr/bin/env python3

from typing import Tuple

# Feel free to import anything you need from the standard library.
import oracle
import crypto

def hex_to_sha1_state_parse(hex_tag: str):
    """Convert 40-char hex digest into list of five 32-bit ints (A, B, C, D, E)."""
    
    if len(hex_tag) != 40:
        raise ValueError("unexpected tag length")
    
    return [int(hex_tag[i*8:(i+1)*8], 16) for i in range(5)]

def main(message: bytes, injection: bytes) -> Tuple[bytes, str]:
#     """ Your goal is to bypass the oracle's integrity check.

#     This will break UF-CMA security of the scheme and demonstrate a length
#     extension attack on the underlying SHA1 hash function, which relies on the
#     Merkle-Damgard construction internally.

#     Specifically, you must somehow craft a message that includes the given
#     parameter WITHIN the default message AND find a valid tag for it WITHOUT
#     querying the oracle.

#     Your attack should be able to inject any message you want, but we want you
#     to include your GT username (as bytes) specifically.
#     """
    if not isinstance(message, bytes) or not isinstance(injection, bytes):
        raise TypeError(f"expected bytes as args, got {type(message)} and {type(injection)}")

    orig_tag = oracle.query(message)

    print("\norig_tag for message:",message)
    print(orig_tag)

    ######### Fixed key length of 64
    ######################### PART A ##################################################################

    fixed_key_length = 64
    pad_fixed = crypto.Sha1.create_padding(message,extra_length=fixed_key_length)
    msg_forged = message + pad_fixed + injection
    state = hex_to_sha1_state_parse(orig_tag)
    al_procssd = fixed_key_length + len(message) + len(pad_fixed)
    tag_forged = crypto.Sha1.sha1(injection, initial_state=state, extra_length=al_procssd)

    if oracle.check(msg_forged, tag_forged):
        return msg_forged, tag_forged

    ###### Brute force 100 bytes key length extension except for the 64 byte which has been processed
    ########################## PART B ################################################################

    for key_len in range(1, 101):
        if key_len != 64:
            print("key length=",key_len)
            pad = crypto.Sha1.create_padding(message, extra_length=key_len)
            msg_forged = message + pad + injection
            state = hex_to_sha1_state_parse(orig_tag)
            al_procssd = key_len + len(message) + len(pad)
            tag_forged = crypto.Sha1.sha1(injection, initial_state=state, extra_length=al_procssd)

            if oracle.check(msg_forged, tag_forged):
                return msg_forged, tag_forged

    return b"", ""
