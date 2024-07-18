import sys

if __name__ == '__main__':
    str = " ".join(sys.argv[1:])
    print("const char picstr[] = { ", end='')
    escape = False
    for c in str:
        if c == '\\':
            escape = True
            continue
        if escape:
            print("'\\", c, "'", ", ", end='', sep='')
            escape = False
        else:
            print("'", c, "'", ", ", end='', sep='')
    print("'\\0' };")
