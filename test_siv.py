#!/usr/bin/env python3
# Test framework for System Integrity Verifier (SIV)
# used in course ET2595 at BTH
#
# Copyright (C) 2019 by Dragos Ilie
# All Rights Reserved.
#
# This code can freely distributed and changed for academic and
# self-study purposes.
import os
import argparse
import shutil
import gzip
import subprocess

def touch(fname, times=None):
    with open(fname, 'a'):
        os.utime(fname, times)

def echo(fname, text, compress=False):
    if compress:
        with gzip.open(fname, 'wb') as fh:
            fh.write(text.encode('utf-8'))
    else:
        with open(fname, "w") as fh:
            print(text, file=fh)

def populate_env(envdir):
    mytext = "Hello"
    muchtext = "Hello\n" * 200
    # Create file if not existing and then write text to it
    echo(envdir + "/data/x.txt", mytext)
    # Create a directory (folder)
    os.mkdir(envdir + "/data/a")
    # Create a directory (folder)
    os.mkdir(envdir + "/data/b")
    # Create file if it does not exist and then set date to "now"
    touch(envdir + "/data/a/blah.txt")
    # Create a file if it does not exist and compress any contents written to it
    echo(envdir + "/data/a/blahblah.gz", muchtext, compress=True)


def change_env(envdir):
    mytext = "Bye"
    # Change content
    echo(envdir + "/data/x.txt", mytext)
    # Change access time to "beginning of time"
    touch(envdir + "/data/x.txt", (0,0))
    # File deleted
    os.remove(envdir + "/data/a/blahblah.gz")
    # Folder deleted
    os.rmdir(envdir + "/data/b")
    # Folder permission bits, owner and group modified
    os.chmod(envdir + "/data/a", 0o777)

    # To run "sudo chown" in below without being prompted 
    # for password enter sudo visudo in a terminal
    # Add the following line after the % sudo line:
    #
    # student  ALL = (ALL) NOPASSWD: / bin/chown
    os.system('sudo /bin/chown brn:root ' + envdir + "/data/x.txt")


def make_env(envdir):
    # check if env directory exists
    if os.path.exists(envdir):
        overwrite = input("Environment exists! Overwrite (y/n)?")
        if overwrite is 'y':
            ## Try to remove tree; if failed show an error using try...except on screen
            try:
                shutil.rmtree(envdir)
            except OSError as e:
                print ("Error: %s - %s." % (e.filename, e.strerror))
                return False
        else:
            print("Execution interrupted due to existing environment directory")
            return False

    os.makedirs(envdir + "/data")
    return populate_env(envdir)


def siv_init(sivexec, envdir):
    siv_cmd = [sivexec, '-i', '-D', envdir + '/data', '-V', envdir + '/vDB', '-R', envdir + '/init.txt', '-H', 'sha1']
    print(' '.join(siv_cmd))
    result = subprocess.run(siv_cmd, stdout=subprocess.PIPE)
    print(result.stdout.decode('utf-8'))
    if result.returncode == 0:
        print("*"*10 + "INIT COMPLETED" + "*"*10)
        return True
    else:
        print("#"*10 + "INIT FAILED" + "#"*10)
        return False

def siv_verify(sivexec, envdir):
    siv_cmd = [sivexec, '-v', '-D', envdir + '/data', '-V', envdir + '/vDB', '-R', envdir + '/verify.txt']
    print(' '.join(siv_cmd))
    result = subprocess.run(siv_cmd, stdout=subprocess.PIPE)
    print(result.stdout.decode('utf-8'))
    if result.returncode == 0:
        print("*"*10 + "VERIFY COMPLETED" + "*"*10)
        return True
    else:
        print("#"*10 + "VERIFY FAILED" + "#"*10)
        return False

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--siv", type=str, dest="sivexec",         required=True)
    parser.add_argument("-e", "--env", type=str, dest="envdir", default="./submission")
    # Do not execute the SIV (because it requires manual exec), just initialize
    # environment
    parser.add_argument("-i", "--init", dest="init_only", action='store_true')
    # Do not execute the SIV (because it requires manual exec), just initialize
    # environment
    parser.add_argument("-v", "--verify", dest="verify_only", action='store_true')

    args = parser.parse_args()
    if args.init_only is True and args.verify_only is True:
        print("--init and --verify are mutually exclusive. Use only one of them")
    if os.path.isfile(args.sivexec) is False:
        print("SIV " + args.sivexec + " is missing")
        return -1
    if args.verify_only is False:
        if make_env(args.envdir) is False:
            print("Unable to create environment")
            return -1
    if args.init_only is False and args.verify_only is False:
        if siv_init(args.sivexec, args.envdir) is False:
            print("Unable to initialize SIV")
            return -1
    if args.init_only is False:
        change_env(args.envdir)
    if args.init_only is False and args.verify_only is False:
        if siv_verify(args.sivexec, args.envdir) is False:
            print("Unable to VERIFY")
            return -1
    print("COMPLETED")


if __name__ == "__main__":
    main()
