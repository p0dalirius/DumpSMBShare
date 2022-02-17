#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DumpSMBShare.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 Feb 2022

import argparse
import logging
import os
import sys
import traceback
from impacket import version
from impacket.examples import logger, utils
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError


class BFSDumpShare(object):
    """docstring for BFSDumpShare."""

    def __init__(self, smb, share, base_dir="", dump_dir="."):
        super(BFSDumpShare, self).__init__()
        self.smb = smb
        self.share = share
        self.dump_dir = dump_dir
        self.base_dir = base_dir
        if not os.path.exists(self.dump_dir):
            os.makedirs(self.dump_dir, exist_ok=True)

    def list_shares(self):
        logging.info("Listing shares ...")
        resp = self.smb.listShares()
        shares = []
        for k in range(len(resp)):
            shares.append(resp[k]["shi1_netname"][:-1])
        return shares

    def dump_share(self, extensions=[], base_dir=None):
        if base_dir is not None:
            self.base_dir = base_dir
        logging.info("Dumping files with extensions %s ... " % extensions)
        # Breadth-first search algorithm to recursively find .extension files
        files = []
        searchdirs = [self.base_dir + "/"]
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                logging.debug("Searching in %s " % sdir)
                try:
                    for sharedfile in self.smb.listPath(self.share, sdir + "*", password=None):
                        if sharedfile.get_longname() not in [".", ".."]:
                            if sharedfile.is_directory():
                                logging.debug("Found directory %s/" % sharedfile.get_longname())
                                next_dirs.append(sdir + sharedfile.get_longname() + "/")
                            else:
                                if len(extensions) == 0 or any([sharedfile.get_longname().endswith("." + e) for e in extensions]):
                                    logging.debug("Found matching file %s" % (sdir + sharedfile.get_longname()))
                                    full_path = sdir + sharedfile.get_longname()
                                    files.append(full_path)
                                    self.dump_file(full_path)
                                else:
                                    logging.debug("Found file %s" % sharedfile.get_longname())
                except SessionError as e:
                    logging.debug(e)
            searchdirs = next_dirs
            logging.debug("Next iteration with %d folders." % len(next_dirs))
        return files

    def dump_file(self, filename):
        # Sanitize dir
        filename = filename.replace("\\", "/")

        _dir, _file = os.path.dirname(filename), os.path.basename(filename)
        if _dir.startswith("//"):
            _dir = _dir[2:]
        try:
            # opening the files in streams instead of mounting shares allows for running the script from
            # unprivileged containers
            # Create directory
            if _dir.startswith(self.base_dir.rstrip('/')):
                _dir = _dir[len(self.base_dir.rstrip('/')):].lstrip('/')
            if not os.path.exists(self.dump_dir + "/" + _dir + "/"):
                os.makedirs(self.dump_dir + "/" + _dir + "/", exist_ok=True)
            # Write file
            path = self.dump_dir + "/" + _dir + "/" + _file
            f = open(path, "wb")
            self.smb.getFile(self.share, filename, f.write)
            f.close()
            return True
        except SessionError as e:
            logging.error(e)
            return False
        except Exception as e:
            raise


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description="")

    parser.add_argument("target", action="store", help="[[domain/]username[:password]@]<targetName or address>")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-share", type=str, default=None, help="SMB Share to dump")
    group.add_argument("-list-shares", default=False, action="store_true", help="Lists SMB shares.")

    parser.add_argument("-extensions", type=str, required=False, default="", help="Extensions")
    parser.add_argument("-dump-dir", type=str, required=False, default=None, help="Dump directory")

    parser.add_argument("-base-dir", type=str, required=False, default="", help="Directory to search in (Default: /)")
    parser.add_argument("-ts", action="store_true", help="Adds timestamp to every logging output")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    group = parser.add_argument_group("authentication")
    group.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes, format is LMHASH:NTHASH")
    group.add_argument("-no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    group.add_argument("-k", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    group.add_argument("-aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")

    group = parser.add_argument_group("connection")

    group.add_argument("-dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    group.add_argument("-target-ip", action="store", metavar="ip address", help="IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it")
    group.add_argument("-port", choices=["139", "445"], nargs="?", default="445", metavar="destination port", help="Destination port to connect to SMB Server")

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


def init_logger(args):
    # Init the example"s logger theme and debug level
    logger.init(args.ts)
    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library"s installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger("impacket.smbserver").setLevel(logging.ERROR)


def init_smb_session(args, domain, username, password, address, lmhash, nthash):
    smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))
    dialect = smbClient.getDialect()
    if dialect == SMB_DIALECT:
        logging.debug("SMBv1 dialect used")
    elif dialect == SMB2_DIALECT_002:
        logging.debug("SMBv2.0 dialect used")
    elif dialect == SMB2_DIALECT_21:
        logging.debug("SMBv2.1 dialect used")
    else:
        logging.debug("SMBv3.0 dialect used")
    if args.k is True:
        smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
    else:
        smbClient.login(username, password, domain, lmhash, nthash)
    if smbClient.isGuestSession() > 0:
        logging.debug("GUEST Session Granted")
    else:
        logging.debug("USER Session Granted")
    return smbClient


if __name__ == "__main__":
    args = parse_args()
    args.extensions = [e.strip() for e in args.extensions.strip().split(",") if len(e.strip()) != 0]
    init_logger(args)

    domain, username, password, address, lmhash, nthash = parse_target(args)

    try:
        smbClient = init_smb_session(args, domain, username, password, address, lmhash, nthash)
        if args.list_shares:
            g = BFSDumpShare(smbClient, args.share, dump_dir=args.dump_dir)
            shares = g.list_shares()
            for s in shares:
                print("  - %s" % s)
            print()
        else:
            if args.dump_dir is None:
                args.dump_dir = "./%s/%s/" % (domain, args.share)
            g = BFSDumpShare(smbClient, args.share, base_dir=args.base_dir, dump_dir=args.dump_dir)
            if args.share in g.list_shares():
                dumped_files = g.dump_share(extensions=args.extensions)
                print("[+] Dumped %d files from share '%s'" % (len(dumped_files), args.share))
            else:
                print("[>] Cannot find share '%s'" % args.share)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))