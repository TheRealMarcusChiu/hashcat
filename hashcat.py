import crypt
import itertools

password_allowed_characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~]'
password_allowed_characters_chars = []
for c in password_allowed_characters:
    password_allowed_characters_chars.append(c)

f = open("hash2.txt", "r")
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
            print(password + ' ' + line)


print('checking passwords of size 1')
for a in itertools.product(password_allowed_characters_chars):
    check(a)

print('checking passwords of size 2')
for a, b in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b)

print('checking passwords of size 3')
for a, b, c in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c)

print('checking passwords of size 4')
for a, b, c, d in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d)

print('checking passwords of size 5')
for a, b, c, d, e in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e)

print('checking passwords of size 6')
for a, b, c, d, e, f in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e + f)

print('checking passwords of size 7')
for a, b, c, d, e, f, g in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e + f + g)

print('checking passwords of size 8')
for a, b, c, d, e, f, g, h in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e + f + g + h)

print('checking passwords of size 9')
for a, b, c, d, e, f, g, h, i in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e + f + g + h + i)

print('checking passwords of size 10')
for a, b, c, d, e, f, g, h, i, j in itertools.product(password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars, password_allowed_characters_chars):
    check(a + b + c + d + e + f + g + h + i + j)

