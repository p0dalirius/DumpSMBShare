#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DumpSMBShare.py
# Author             : Podalirius (@podalirius_)
# Date created       : 6 Jul 2022

import argparse
import os
import sys
import traceback
from impacket import version
from impacket.examples import logger, utils
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError


class BFSDumpShare(object):
    """docstring for BFSDumpShare."""

    def __init__(self, smb, share, base_dir="", dump_dir=".", quiet=False, debug=False, only_list_files=False):
        super(BFSDumpShare, self).__init__()
        self.quiet = quiet
        self.debug = debug

        self.smb = smb
        self.share = share
        self.dump_dir = dump_dir
        self.base_dir = base_dir
        self.only_list_files = only_list_files
        if not os.path.exists(self.dump_dir):
            os.makedirs(self.dump_dir, exist_ok=True)

    def list_shares(self):
        print("[>] Listing shares ...")
        resp = self.smb.listShares()
        shares = []
        for k in range(len(resp)):
            shares.append(resp[k]["shi1_netname"][:-1])
        return shares

    def dump_share(self, targetfile="", extensions=[], base_dir=None):
        if base_dir is not None:
            self.base_dir = base_dir
        print("[>] Dumping files with extensions %s ... " % extensions)
        # Breadth-first search algorithm to recursively find .extension files
        files = []
        searchdirs = [self.base_dir + "/"]
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                if self.debug:
                    print("[>] Searching in %s " % sdir)
                try:
                    for sharedfile in self.smb.listPath(self.share, sdir + "*", password=None):
                        if sharedfile.get_longname() not in [".", ".."]:
                            if sharedfile.is_directory():
                                if self.debug:
                                    print("[>] Found directory %s/" % sharedfile.get_longname())
                                next_dirs.append(sdir + sharedfile.get_longname() + "/")
                            else:
                                if len(extensions) == 0 or any([sharedfile.get_longname().endswith("." + e) for e in extensions]) or sharedfile.get_longname() == targetfile:
                                    if self.debug or not self.quiet or self.only_list_files:
                                        print("[>] Found matching file %s" % (sdir + sharedfile.get_longname()))
                                    full_path = sdir + sharedfile.get_longname()
                                    files.append(full_path)
                                    if not self.only_list_files:
                                        self.dump_file(full_path)
                                else:
                                    if self.debug:
                                        print("[>] Found file %s" % sharedfile.get_longname())
                except SessionError as e:
                    if self.debug:
                        print("[error] %s " % e)
            searchdirs = next_dirs
            if self.debug:
                print("[>] Next iteration with %d folders." % len(next_dirs))
        return files

    def dump_file(self, filepath, only_file=False):
        # Sanitize dir
        filepath = filepath.replace("\\", "/")

        _dir, _file = os.path.dirname(filepath), os.path.basename(filepath)
        if _dir.startswith("//"):
            _dir = _dir[2:]
        try:
            if only_file:
                if not os.path.exists(self.dump_dir):
                    os.makedirs(self.dump_dir, exist_ok=True)
                path = self.dump_dir + "/" + _file
            else:
                # Create directory
                if _dir.startswith(self.base_dir.rstrip('/')):
                    _dir = _dir[len(self.base_dir.rstrip('/')):].lstrip('/')
                if not os.path.exists(self.dump_dir + "/" + _dir + "/"):
                    os.makedirs(self.dump_dir + "/" + _dir + "/", exist_ok=True)
                path = self.dump_dir + "/" + _dir + "/" + _file
            # Write file
            f = open(path, "wb")
            self.smb.getFile(self.share, filepath, f.write)
            f.close()
            return True
        except SessionError as e:
            if self.debug:
                print("[error] %s" % e)
            return False
        except Exception as e:
            raise


def parse_args():
    print("DumpSMBShare v1.3 - by @podalirius_\n")

    parser = argparse.ArgumentParser(add_help=True, description="A script to dump files and folders remotely from a Windows SMB share.")

    parser.add_argument("target", action="store", help="[[domain/]username[:password]@]<targetName or address>")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--share", type=str, default=None, help="SMB Share to dump")
    group.add_argument("-l", "--list-shares", default=False, action="store_true", help="Lists SMB shares on the remote machine.")

    parser.add_argument("-L", "--list-files", default=False, action="store_true", help="Lists all the files present in the SMB share.")

    parser.add_argument("-e", "--extensions", type=str, required=False, default="", help="Extensions")
    parser.add_argument("-D", "--dump-dir", type=str, required=False, default=None, help="Dump directory")
    parser.add_argument("-f", "--file", type=str, default=None, help="SMB file to dump")

    parser.add_argument("-B", "--base-dir", type=str, required=False, default="", help="Directory to search in (Default: /)")
    parser.add_argument("--debug", action="store_true", help="Turn on debug output. (Default: False)")
    parser.add_argument("-q", "--quiet", action="store_true", default=False, help="Turn DEBUG output ON")

    group = parser.add_argument_group("authentication")
    group.add_argument("-H", "--hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes, format is LMHASH:NTHASH")
    group.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    group.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    group.add_argument("-A", "--aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")

    group = parser.add_argument_group("connection")

    group.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    group.add_argument("-I", "--target-ip", action="store", metavar="ip address", help="IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it")
    group.add_argument("-P", "--port", choices=["139", "445"], nargs="?", default="445", metavar="destination port", help="Destination port to connect to SMB Server")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def parse_target(args):
    domain, username, password, address = utils.parse_target(args.target)
    if args.target_ip is None:
        args.target_ip = address
    if domain is None:
        domain = ""
    if password == "" and username != "" and args.hashes is None and args.no_pass is False and args.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")
    if args.aesKey is not None:
        args.k = True
    if args.hashes is not None:
        lmhash, nthash = args.hashes.split(":")
    else:
        lmhash = ""
        nthash = ""
    return domain, username, password, address, lmhash, nthash


def init_smb_session(args, domain, username, password, address, lmhash, nthash):
    smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))
    dialect = smbClient.getDialect()
    if dialect == SMB_DIALECT:
        if args.debug:
            print("[>] SMBv1 dialect used")
    elif dialect == SMB2_DIALECT_002:
        if args.debug:
            print("[>] SMBv2.0 dialect used")
    elif dialect == SMB2_DIALECT_21:
        if args.debug:
            print("[>] SMBv2.1 dialect used")
    else:
        if args.debug:
            print("[>] SMBv3.0 dialect used")
    if args.kerberos is True:
        smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
    else:
        smbClient.login(username, password, domain, lmhash, nthash)
    if smbClient.isGuestSession() > 0:
        if args.debug:
            print("[>] GUEST Session Granted")
    else:
        if args.debug:
            print("[>] USER Session Granted")
    return smbClient


if __name__ == "__main__":
    args = parse_args()
    args.extensions = [e.strip() for e in args.extensions.strip().split(",") if len(e.strip()) != 0]

    domain, username, password, address, lmhash, nthash = parse_target(args)

    try:
        smbClient = init_smb_session(args, domain, username, password, address, lmhash, nthash)
        if args.list_shares:
            if args.dump_dir is None:
                g = BFSDumpShare(smbClient, args.share)
            else:
                g = BFSDumpShare(smbClient, args.share, dump_dir=args.dump_dir)
            shares = g.list_shares()
            for s in shares:
                print("  - %s" % s)
            print()
        else:
            if args.dump_dir is None:
                args.dump_dir = "./%s/%s/" % (address, args.share)
            g = BFSDumpShare(smbClient, args.share, base_dir=args.base_dir, dump_dir=args.dump_dir, quiet=args.quiet, debug=args.debug, only_list_files=args.list_files)
            if args.share in g.list_shares():
                if args.file is not None:
                    print("[+] Dumping file '%s' from share '%s'" % (args.file, args.share))
                    g.base_dir = os.path.basename(args.base_dir)
                    g.dump_file(args.file, only_file=True)
                else:
                    dumped_files = g.dump_share(extensions=args.extensions)
                    if not args.list_files:
                        print("[+] Dumped %d files from share '%s'" % (len(dumped_files), args.share))
            else:
                print("[>] Cannot find share '%s'" % args.share)
    except Exception as e:
        raise e
