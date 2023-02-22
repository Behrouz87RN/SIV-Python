#!/usr/bin/env python3

import argparse
import csv
import datetime
import grp
import hashlib
import os
import pwd
import sys

def printError(*args, **kwargs):
    
 print(*args, file=sys.stderr, **kwargs)


def isSubDirPath(base, subDirPath):
    #Check contains subpath

    absBase = os.path.realpath(base)

    # Attach separator at the end
    absBase += '' if absBase.endswith(os.path.sep) else os.path.sep

    return os.path.realpath(subDirPath).startswith(absBase)


def confirmPrompt(text):
    answer = input(text + " [Y/n]: ")
    while 1:
        if answer == '' or answer.lower() == 'y':
            return True
        elif answer.lower() == 'n':
            return False

        answer = input("[Y/n]: ")

#get the hash file content

def getFileHash(file, hash_object, block_size=65536):
   
    try:
        with open(file, 'rb') as f:
            buffer = f.read(block_size)
            while len(buffer) > 0:
                hash_object.update(buffer)
                buffer = f.read(block_size)
    except IOError:
        return None

    return hash_object.hexdigest()


class WalkStats:
    totalDirectories = 0
    totalFiles = 0


class FileInfo:
    def __init__(self, path=None, size=None, user=None, group=None, mode=None,
                 modified=None, verificationHash=None):
        self.path = path
        self.size = None if not size else int(size)
        self.user = user
        self.group = group
        self.mode = mode
        self.modified = modified
        self.verificationHash = verificationHash or None

    def __bool__(self):
        return bool(self.path)


def walkDirectorySorted(path, hash_object, walk_stats_object):
   
    infoFile = FileInfo()

    abs_path = os.path.abspath(path)

    # list of files and directories

    all_files = []
    for root, dirs, files in os.walk(abs_path):
        walk_stats_object.totalDirectories += len(dirs)
        walk_stats_object.totalFiles += len(files)

        for f in files + dirs:
            all_files.append(os.path.join(root, f))

    # get information of file

    for file_path in sorted(all_files):
        infoFile.path = file_path
        file_stat = os.stat(infoFile.path)

        infoFile.size = file_stat.st_size
        infoFile.user = pwd.getpwuid(file_stat.st_uid).pw_name
        infoFile.group = grp.getgrgid(file_stat.st_gid).gr_name
        infoFile.mode = oct(file_stat.st_mode)  #  777 permission
        infoFile.modified = datetime.datetime \
            .fromtimestamp(file_stat.st_mtime) \
            .strftime('%Y-%m-%d %H:%M:%S')

        if os.path.isfile(infoFile.path):
            infoFile.verificationHash = getFileHash(infoFile.path,
                                               hash_object.copy())
            if not infoFile.verificationHash:
                printError("Error: Unable read file {}".format(infoFile.path))
        else:
            infoFile.verificationHash = None
        yield infoFile


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description='SIV-System Integrity Verifier.',
    epilog='Example:\n'
           '    {} -i -D /etc/ -V db.csv -R report.txt -H md5\n'
           '    {} -v -D /etc/ -V db.csv -R report.txt'.format(sys.argv[0],
                                                               sys.argv[0]))
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-i', action='store_true', dest='initiation_mode',
                   help='enable initiation mode')
group.add_argument('-v', action='store_true', dest='verification_mode',
                   help='enable verification mode')
parser.add_argument('-D', type=str, required=True, dest='monitoredDir',
                    help='directory to be monitored')
parser.add_argument('-V', type=str, required=True, dest='verification_file',
                    help='verification database file')
parser.add_argument('-R', type=str, required=True, dest='report_file',
                    help='destination of the text file report')
parser.add_argument('-H', type=str, dest='hash_function',
                    choices=list(hashlib.algorithms_guaranteed),
                    help='hashing algorithm (only for initiation mode)')

args = parser.parse_args()

# Initial mode
if args.initiation_mode:
    print('Initiation mode...')

    if not args.hash_function:
        printError("Error: there is no hashing algorithm specified. "
               "use option '-H'")
        sys.exit()

    if not os.path.exists(args.monitoredDir):
        printError("Error: monitored directory '{}' does not exist"
               .format(args.monitoredDir))
        sys.exit()

    if not os.path.isdir(args.monitoredDir):
        printError("Error: monitored directory '{}' is not a directory"
               .format(args.monitoredDir))
        sys.exit()

    if isSubDirPath(args.monitoredDir, args.verification_file):
        printError("Error: verification file ('{}') exists inside monitored "
               "directory ('{}')".format(args.verification_file,
                                         args.monitoredDir))
        sys.exit()

    if isSubDirPath(args.monitoredDir, args.report_file):
        printError("Error: report file ('{}') exists inside monitored directory "
               "('{}')".format(args.report_file, args.monitoredDir))
        sys.exit()

    if os.path.exists(args.verification_file):
        printError("Error: Verification file '{}' already exists"
               .format(args.verification_file))
        if not confirmPrompt("Overwrite on existing verification file?"):
            sys.exit()

    if os.path.exists(args.report_file):
        printError("Error: Report file '{}' already exists"
               .format(args.report_file))
        if not confirmPrompt("Overwrite on existing Report file?"):
            sys.exit()

    hash_object = hashlib.new(args.hash_function)
    walk_stats = WalkStats()
#Write row pf file info
    with open(args.verification_file, 'w') as verification_handle:
        verification_writer = csv.writer(verification_handle)
        verification_writer.writerow([args.hash_function])

        dt_start = datetime.datetime.now()

        for infoFile in walkDirectorySorted(args.monitoredDir,
                                               hash_object, walk_stats):
            verification_writer.writerow([infoFile.path, infoFile.size,
                                          infoFile.user, infoFile.group,
                                          infoFile.mode, infoFile.modified,
                                          infoFile.verificationHash])

        dt_end = datetime.datetime.now()

        elapsed_seconds = (dt_end - dt_start).total_seconds()

    with open(args.report_file, 'w') as f:
        f.write("Monitored directory   : {}\n"
                .format(os.path.abspath(args.monitoredDir)))
        f.write("Verification file     : {}\n"
                .format(os.path.abspath(args.verification_file)))
        f.write("Number of directories : {}\n"
                .format(walk_stats.totalDirectories))
        f.write("Number of files       : {}\n"
                .format(walk_stats.totalFiles))
        f.write("Execution time        : {}s\n"
                .format(elapsed_seconds))
            
    print("Report File generated")
    print ("Initiation Completed")
    
#Verification mode
if args.verification_mode:
    print('Verification mode...')

    if not os.path.isfile(args.verification_file):
        printError("Error: verification file '{}' does not exist"
               .format(args.verification_file))
        sys.exit()

    if isSubDirPath(args.monitoredDir, args.verification_file):
        printError("Error: verification file '{}' exists in monitored "
               "directory '{}'".format(args.verification_file,
                                       args.monitoredDir))
        sys.exit()

    if isSubDirPath(args.monitoredDir, args.report_file):
        printError("Error: report file '{}' exists in monitored "
               "directory '{}'".format(args.report_file,
                                       args.monitoredDir))
        sys.exit()

    walk_stats = WalkStats()
    num_warnings = 0

    with open(args.verification_file, 'r') as verification_handle, \
            open(args.report_file, 'w') as report_handle:
        dt_start = datetime.datetime.now()

        iter_old = csv.reader(verification_handle)

        hash_algorithm = next(iter_old)[0]
        hash_object = hashlib.new(hash_algorithm)

        iter_new = walkDirectorySorted(args.monitoredDir,
                                         hash_object, walk_stats)

        o_file = FileInfo(*next(iter_old, []))
        n_file = next(iter_new, None)
        while o_file or n_file:
            if ((not o_file and n_file) or
                    (o_file and n_file and o_file.path > n_file.path)):
                # Find a new file

                report_handle.write('+{} Was added\n'.format(n_file.path))
                num_warnings += 1

                n_file = next(iter_new, None)
            elif ((o_file and not n_file) or
                  (o_file and n_file and o_file.path < n_file.path)):
                # find the file deleted

                report_handle.write('-{} Was deleted\n'.format(o_file.path))
                num_warnings += 1

                o_file = FileInfo(*next(iter_old, []))
            elif o_file and n_file and o_file.path == n_file.path:
                # Same file is detected

                if o_file.size != n_file.size:
                    report_handle.write('*{}, Size of file: {} -> {}\n'
                                        .format(o_file.path, o_file.size,
                                                n_file.size))
                    num_warnings += 1

                if o_file.user != n_file.user:
                    report_handle.write('*{}, Owner of file: {} -> {}\n'
                                        .format(o_file.path, o_file.user,
                                                n_file.user))
                    num_warnings += 1

                if o_file.group != n_file.group:
                    report_handle.write('*{}, Group of file: {} -> {}\n'
                                        .format(o_file.path, o_file.group,
                                                n_file.group))
                    num_warnings += 1

                if o_file.mode != n_file.mode:
                    report_handle.write('*{}, Mode: {} -> {}\n'
                                        .format(o_file.path, o_file.mode,
                                                n_file.mode))
                    num_warnings += 1

                if o_file.modified != n_file.modified:
                    report_handle.write('*{}, Last modified: {} -> {}\n'
                                        .format(o_file.path, o_file.modified,
                                                n_file.modified))
                    num_warnings += 1

                if o_file.verificationHash != n_file.verificationHash:
                    report_handle.write('*{}, Verification Hash: {} -> {}\n'
                                        .format(o_file.path, o_file.verificationHash,
                                                n_file.verificationHash))
                    num_warnings += 1

                o_file = FileInfo(*next(iter_old, []))
                n_file = next(iter_new, None)
            else:
                raise Exception("logic error!")
        dt_end = datetime.datetime.now()

        elapsed_seconds = (dt_end - dt_start).total_seconds()

        report_handle.write("Monitored Directory of file   : {}\n"
                            .format(os.path.abspath(args.monitoredDir)))
        report_handle.write("Verification file     : {}\n"
                            .format(os.path.abspath(args.verification_file)))
        report_handle.write("Report_file     : {}\n"
                            .format(os.path.abspath(args.report_file)))
        report_handle.write("Number of Files       : {}\n"
                            .format(walk_stats.totalFiles))
        report_handle.write("Number of Directories : {}\n"
                            .format(walk_stats.totalDirectories))
        report_handle.write("Time of Execution        : {}s\n"
                            .format(elapsed_seconds))
        report_handle.write("The Number of Warnings    : {}\n"
                            .format(num_warnings))
        
    print("Report File generated")              
    print ("Verifiction Completed")
                            
                            
