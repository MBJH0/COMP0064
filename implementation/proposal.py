from sys import argv

from src import mitm, auth


def main():
    if len(argv) > 5 or len(argv) < 3:
        print(f"ERROR: Incorrect number of parameters passed.")
        return
    debug = False
    if "-d" in argv:
        debug = True
    if "-r" in argv:
        mode = "-r"
        mode_index = argv.index("-r")
    elif "-t" in argv:
        mode = "-t"
        mode_index = argv.index("-t")
    else:
        print("ERROR: Mode was not indicated.")
        return
    address1, port1 = argv[mode_index+1].split(':')
    if mode in ["-r", "--run"]:
        auth.run(address=(address1, int(port1)), debug=debug)
    elif mode in ["-t", "--test"]:
        address2, port2 = argv[mode_index+2].split(':')
        mitm.run(address1=(address1, int(port1)), address2=(address2, int(port2)), debug=debug)


if __name__ == '__main__':
    # python3 proposal.py [-r | --run] address:port
    # python3 proposal.py [-t | --test] address:port address:port
    main()
