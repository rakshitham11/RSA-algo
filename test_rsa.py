import rsa_algorithm as r
assert r.text_to_numbers("HELLO") == [72, 69, 76, 76, 79]
assert r.text_to_numbers("RSA") == [82, 83, 65]
assert r.text_to_numbers("ABC") == [65, 66, 67]
assert r.text_to_numbers("a Z~") == [97, 32, 90, 126]
k = r.generate_keys(61, 53); assert (k["n"], k["phi"], k["e"], k["d"]) == (3233, 3120, 17, 2753)
for p, q in [(61, 53), (101, 103), (17, 11), (1009, 1013)]:
    for msg in ["Hello, World!", "RSA", "ABC", " a  Z ", "<b>&amp;</b> ~!@#", "".join(map(chr, range(32, 127)))]:
        e = r.encrypt_message(p, q, msg)
        assert r.decrypt_message(p, q, e["cipher"])["plaintext"] == msg, (p, q, msg)
for bad in [(4, 53, "A"), (61, 61, "A"), (2, 13, "A"), (5, 7, "A"), (61, 53, "caf\u00e9"), (61, 53, ""), (61, 53, "tab\t")]:
    try: r.encrypt_message(*bad); raise SystemExit("no error " + str(bad))
    except r.RSAError as ex: pass
assert r.generate_keys(61, 53, 7)["e"] == 7 and r.generate_keys(61, 53, "")["e"] == 17
assert r.generate_keys(1009, 1013, 65537)["e"] == 65537
for e, frag in [(65537, "smaller"), (5, "gcd"), (1, "greater"), ("abc", "whole")]:
    try: r.generate_keys(61, 53, e); raise SystemExit("no error e")
    except r.RSAError as ex: assert frag in str(ex), ex
print("all tests passed")
