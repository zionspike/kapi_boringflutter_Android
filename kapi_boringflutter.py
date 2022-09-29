import r2pipe
import time
import sys
import os

# brew install radare2
# pip install r2pipe

search_string = "ssl_client"


def argument_parsing():
    if len(sys.argv) < 2:
        print('[!]  Usage: python {} libflutter.so'.format(sys.argv[0]))
        exit(-1)

    if not os.path.exists(sys.argv[1]):
        print('[!]  File "{}" not found...'.format(sys.argv[1]))
        exit(-1)

    if not os.path.isfile(sys.argv[1]):
        print('[!]  "{}" is a directory, please provide a valid libflutter.so file...'.format(sys.argv[1]))
        exit(-1)
    return sys.argv[1]


def arch_parsing(r2):
    info = r2.cmdj('ij')
    info_bin = info.get('bin')
    if not info_bin:
        print('[!]  File "{}" is not a binary...'.format(sys.argv[1]))
        exit(0)

    if info_bin.get('os') != 'android':
        print('[!]  Currently only supporting Android...')
        exit(0)

    if info_bin.get('arch') != 'arm':
        print('[!]  Currently only supporting ARM...')
        exit(0)

    return int(info_bin.get('class')[3:])


def perform_64bits_analysis(r2):
    print('[+] Performing Advanced analysis (aaaa)...')
    r2.cmd('aaaa')

    print('[+] Searching for instructions with string (iz~{})...'.format(search_string))
    r2res = r2.cmd('iz~{},'.format(search_string))
    print("[!] search: {}".format(r2res))
    r2res = r2res.split()
    string_addr = r2res[1]
    print('[+] Searching for xref (axt {})...'.format(string_addr))
    r2res = r2.cmdj('axtj {}'.format(string_addr))
    # print("[!] r2res: {}".format(r2res))
    addr = r2res[0].get('fcn_name')
    print("[!] addr: {}".format(addr))
    return addr

def perform_32bits_analysis(r2):
    print("32 bits, to do bro...")


if __name__ == "__main__":
    start_time = time.time()

    file = argument_parsing()

    r2 = r2pipe.open(file)
    bits = arch_parsing(r2)

    print('[+] Detected Android ARM {} bits...'.format(bits))
    if bits == 64:
        address = perform_64bits_analysis(r2)
    elif bits == 32:
        address = perform_32bits_analysis(r2)
    else:
        print('[!]  Quantum???')
        exit(-1)

    print("[!] Found address: {}".format(address))
    print('🚀 exec time: {}s'.format(time.time() - start_time))
