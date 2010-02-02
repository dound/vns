#!/usr/bin/env python

import logging
from optparse import OptionParser
from os import chdir, getenv
import re
from socket import inet_aton, inet_ntoa
import struct
from subprocess import Popen, PIPE, STDOUT
from sys import argv, exit
import time

def main(argv=argv[1:]):
    """Parse command-line arguments, start the VNS client if requested, and then
    run the tests."""
    usage = """usage: %prog [options]
Tests an sr topology and reports RTT and throughput statistics."""
    parser = OptionParser(usage)

    # vns client options
    parser.add_option("-a", "--auth_key_file",
                      default="auth_key", metavar="AUTH_FN",
                      help="file to read the auth key from [default: %default]")
    parser.add_option("-c", "--client",
                      default='sr', metavar="CLIENT_FN",
                      help="path to the VNS client program to run [default: %default]")
    parser.add_option("-p", "--path",
                      default='./',
                      help="path to sr (will become the working directory) [default: %s]")
    parser.add_option("-r", "--rtable",
                      default='rtable', metavar="RTABLE_FN",
                      help="file to read the routing table from [default: %default]")
    parser.add_option("-s", "--server",
                      default="vns-2.stanford.edu",
                      help="IP or hostname of the VNS server [default: %default]")
    parser.add_option("-t", "--topology",
                      type="int", metavar="TOPO",
                      help="file to read the routing table from [default: do not run a client]")
    parser.add_option("-u", "--user",
                      default=getenv('LOGNAME'),
                      help="username to connec to VNS with [default: %default]")
    parser.add_option("-v", "--verbose",
                      action='store_true', default=False,
                      help="whether to print verbosely")

    (options, args) = parser.parse_args(argv)
    if len(args) > 0:
        parser.error("too many arguments (did not expect: %s)" % str(args))

    if options.verbose:
        logging.getLogger().setLevel(logging.INFO)

    # start the VNS client, if requested
    if options.topology:
        try:
            chdir(options.path)
        except OSError as e:
            logging.error("unable to change folders to '%s': %s" % (options.path, e))

        try:
            if options.path[-1] != '/':
                options.path += '/'
            cmd = [options.path + options.client,
                   '-a' + options.auth_key_file,
                   '-r' + options.rtable,
                   '-s' + options.server,
                   '-t' + str(options.topology),
                   '-u' + options.user]
            logging.info('Starting VNS client: %s' % ' '.join(cmd))
            vns_client = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        except OSError as e:
            logging.error("unable to run the VNS client '%s': %s" % (options.client, e))
            return -1

        time.sleep(0.5)
        if vns_client.poll():
            output, output_e = vns_client.communicate()
            logging.warning('VNS client terminated unexpectedly: %d\n%s\n%s' % (vns_client.returncode, '' if not output else output, '' if not output_e else output_e))
            return -1
    else:
        vns_client = None

    try:
        rtr_ips, server_ips = __get_ips(options.rtable)
    except IOError as e:
        logging.error("unable to read the rtable file '%s': %s" % (options.rtable, e))
        return -1

    return run_test(vns_client, rtr_ips, server_ips)

RE_FIRST_IP = re.compile(r'^(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\w.*)$')
def __parse_ip(line):
    """Parse an IP from an rtable line."""
    ret = RE_FIRST_IP.search(line)
    assert ret and len(ret.groups())==1, "line does not contain IP at the beginning as expected: %s" % line
    return struct.unpack('>I', inet_aton(ret.group(1)))[0]

def __get_ips(rtable_fn):
    """Gets the IPs for an sr topology based on its rtable file (this function
    assumes that the rtable has three lines and that the second one is the route
    to the first app server; it also assumes the standard sr topology).  A
    2-tuple of lists is returned.  The first list is of router interface IPs.
    The second list contains application server IPs."""
    f = open(rtable_fn, 'r')
    lines = f.readlines()
    f.close()

    if len(lines) < 3:
        raise IOError("rtable does not have 3 lines as expected")
    ip_app1 = __parse_ip(lines[1])
    ips_nbo = (ip_app1-5, ip_app1-1, ip_app1+1, ip_app1, ip_app1+2)
    ips_str = [inet_ntoa(struct.pack('>I', ip)) for ip in ips_nbo]
    return (ips_str[0:3], ips_str[3:5])

def run(program, *args):
    """Run the specified program.  Return its return code, standard output, and
    standard error output as a 3-tuple.  Each element will be None if the
    program cannot be run."""
    try:
        p = Popen([program] + list(args), stdout=PIPE, stderr=PIPE)
    except OSError as e:
        logging.error("unable to run '%s': %s" % (program, e))
        return (None, None, None)
    stdoutdata, stderrdata = p.communicate()
    code = int(p.returncode)
    return (code, stdoutdata, stderrdata,)

RE_PING_RECV = re.compile(r'(\d+) received')
STR_RTT = r'\d+[.]\d+'
RE_PING_AVG_RTT = re.compile(r'rtt min/avg/max/mdev = %s/(%s)/%s/%s ms' % (STR_RTT, STR_RTT, STR_RTT, STR_RTT))
def get_rtt(ip, num_pings_to_send=5, interval=1.0, final_wait_time=1):
    """Sends the requested number of echo requests at the requested interval.
    final_wait_time specifies the maximum number of seconds (an integer) which
    will be waited for a reply AFTER the last echo request is sent.  A 2-tuple
    is returned which contains the number of successful echo replies received as
    well as the average RTT of received replies.  The 'ping' program is used to
    accomplish this."""
    total_wait_time = num_pings_to_send * interval + final_wait_time
    logging.info('Sending %d pings to %s' % (num_pings_to_send, ip))
    code, output, output_e = run('ping',
                                 '-c %d' % num_pings_to_send,
                                 '-i %0.1f' % interval,
                                 '-W %d' % total_wait_time,
                                 ip)
    ret = RE_PING_RECV.search(output)
    if not ret:
        logging.error("unable to find 'received' line in ping output:\n%s" % output)
        return (0, float('inf'))

    num_echo_replies = int(ret.group(1))
    if num_echo_replies == 0:
        logging.info('No replies received')
        return (0, float('inf'))

    ret = RE_PING_AVG_RTT.search(output)
    if not ret:
        logging.error("unable to find 'avg rtt' line in ping output:\n%s" % output)
        return (num_echo_replies, float('inf'))

    avg_rtt = float(ret.group(1))
    logging.info('Got %d replies from %s with average RTT of %0.2f' % (num_echo_replies, ip, avg_rtt))
    return (num_echo_replies, avg_rtt)

def get_rtt_for_ips(ips, num_pings_to_send, interval, final_wait_time):
    """Returns a 2-tuple of the percentage of echo replies which were answered
    and the average RTT.  Uses get_rtt."""
    num_replies = 0
    rtt_tot = 0.0
    for ip in ips:
        nr, rtt = get_rtt(ip, num_pings_to_send, interval, final_wait_time)
        num_replies += nr
        rtt_tot += rtt

    num_ips = len(ips)
    percent_ok = num_replies / float(num_ips * num_pings_to_send)
    avg_rtt = rtt_tot / num_ips
    return (percent_ok, avg_rtt)

RE_GET_THROUGHPUT = re.compile(r'[(](\d+) ([KMG]?B)/s[)]')
def get_throughput(ip, path_to_get, verify_against, proto='http', tries=1, read_timeout=5):
    """Returns a 2-tuple of whether the download was correct and average
    throughput.  If verify_against is none, then the download will not be
    checked and the first element in the 2-tuple will be None.  The 'wget'
    program is used to accomplish (and 'diff' for verification)."""
    url = '%s://%s/%s' % (proto, ip, path_to_get)
    if verify_against:
        output_file = './.tmp_to_verify'
        run('rm', '-f', output_file)
    else:
        output_file = '-'
    logging.info('Retrieving %s' % url)
    code, output, output_e = run('wget',
                                 '-O%s' % output_file, url,
                                 '--tries', str(tries),
                                 '--read-timeout', str(read_timeout))

    if code != 0:
        logging.warning("failed to download %s (giving no credit for this)" % url)
        return (False, 0.0)

    ret = RE_GET_THROUGHPUT.search(output_e)
    if not ret:
        logging.error("unable to find throughput line in wget stderr output:\n%s" % output_e)
        return (False, 0.0)

    # verify if requested
    if verify_against:
        code, output, output_e = run('diff', verify_against, output_file)
        if code != 0:
            logging.warning("downloaded file differs (giving no credit for this; will leave downloaded file in directory as %s)" % output_file)
            return (False, 0.0)
        else:
            logging.info('Verified retrieved URL %s against reference %s' % (url, verify_against))
            run('rm', '-f', output_file)

    Bps = int(ret.group(1))
    bps = 8 * Bps
    units = ret.group(2)
    logging.info('Retrieved URL %s at %d %s/s' % (url, Bps, units))
    if units == 'B':
        return (True, bps)
    elif units == 'KB':
        return (True, 1024*bps)
    elif units == 'MB':
        return (True, 1024*1024*bps)
    else:
        logging.error("unknown units on wget throughput:\n%s" % output_e)
        return (True, 0.0)

def run_test(vns_client, rtr_ips, svr_ips,
             num_pings_to_send=5, interval=1.0, final_wait_time=1,
             num_http_gets=1, proto='http', path_to_get='big.jpg', verify_against='./big.jpg'):
    # get ping stats for each router interface and server IP
    logging.info('Conducting ping/RTT tests to each router and server interface ... ')
    ping_percent_reply_rtr, ping_rtt_rtr = get_rtt_for_ips(rtr_ips, num_pings_to_send, interval, final_wait_time)
    ping_percent_reply_svr, ping_rtt_svr = get_rtt_for_ips(svr_ips, num_pings_to_send, interval, final_wait_time)

    # get throughput stats
    logging.info('Conducting throughput tests to each server ... ')
    i = 0
    xput_num_ok = 0
    xput_tot_bps = 0.0
    while i < num_http_gets:
        # alternate which server we go through (shouldn't really matter)
        server_ip = svr_ips[i % len(svr_ips)]
        ok, xput_bps = get_throughput(server_ip, path_to_get, verify_against, proto)
        if ok:
            xput_num_ok += 1
            xput_tot_bps += xput_bps
        i += 1
    xput_percent_ok = xput_num_ok / num_http_gets
    xput_avg_kbps = (xput_tot_bps / 1024.0) / num_http_gets

    # if we started a VNS client, then stop it
    if vns_client:
        logging.info('Closing the VNS client')
        vns_client.kill()
        logging.info('VNS client closed')

    # report the results
    print '''Results:
\tGroup\t%%PingOk\tRTT(ms)\t%%WgetOk\tAvgXput(kbps)
\tRouter\t%0.1f\t%0.1f\tn/a\tn/a
\tServer\t%0.1f\t%0.1f\t%0.1f\t%0.1f
''' % (ping_percent_reply_rtr, ping_rtt_rtr,
       ping_percent_reply_svr, ping_rtt_svr, xput_percent_ok, xput_avg_kbps)

if __name__ == '__main__':
    logging.basicConfig(format='%(levelname)-8s %(funcName)s:%(lineno)d  %(message)s', level=logging.WARNING)
    exit(main())
