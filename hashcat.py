import crypt
import itertools
import sys

password_allowed_characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~]'
password_allowed_characters_chars = []
for c in password_allowed_characters:
    password_allowed_characters_chars.append(c)

f = open(sys.argv[1], "r")
raw_lines = f.readlines()
f.close()
lines = []
for raw_line in raw_lines:
    lines.append(raw_line.strip())


def check(password):
    for line in lines:
        salt_value = line[0:12]
        hash_value = line[12:]
        hash_value_g = crypt.crypt(password, salt_value)[12:]
        if hash_value_g == hash_value:
            with open(sys.argv[1] + ".output", "a") as out_file:
                out_file.write(password + ' ' + line + '\n')


check('pass')

with open(sys.argv[1] + ".output", "a") as out_file:
    out_file.write('checking passwords of size 1\n')
for a in itertools.product(password_allowed_characters_chars):
    check(str(a))

with open(sys.argv[1] + ".output", "a") as out_file:
    out_file.write('checking passwords of size 2\n')
for a, b in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b)

with open(sys.argv[1] + ".output", "a") as out_file:
    out_file.write('checking passwords of size 3\n')
for a, b, c in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c)

with open(sys.argv[1] + ".output", "a") as out_file:
    out_file.write('checking passwords of size 4\n')
for a, b, c, d in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d)

with open(sys.argv[1] + ".output", "a") as out_file:
    out_file.write('checking passwords of size 5\n')
for a, b, c, d, e in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e)

with open(sys.argv[1] + ".output", "a") as out_file:
    out_file.write('checking passwords of size 6\n')
for a, b, c, d, e, f in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e + f)

with open(sys.argv[1] + ".output", "a") as out_file:
    out_file.write('checking passwords of size 7\n')
for a, b, c, d, e, f, g in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e + f + g)

with open(sys.argv[1] + ".output", "a") as out_file:
    out_file.write('checking passwords of size 8\n')
for a, b, c, d, e, f, g, h in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e + f + g + h)

with open(sys.argv[1] + ".output", "a") as out_file:
    out_file.write('checking passwords of size 9\n')
for a, b, c, d, e, f, g, h, i in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e + f + g + h + i)

with open(sys.argv[1] + ".output", "a") as out_file:
    out_file.write('checking passwords of size 10\n')
for a, b, c, d, e, f, g, h, i, j in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e + f + g + h + i + j)

