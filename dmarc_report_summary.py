#!/usr/bin/env python

import os
import sys
import re
import socket
import struct
import time

import spf # get ips of domain

def get_record_info(content):
    record = {'source_ip': '', 'count': 0, 'dkim': '', 'spf': ''}
    for pattern in record:
        m = re.search("<%s>(.*)</%s>" % (pattern, pattern), content)
        if not m:
            continue
        record[pattern] = m.group(1)
    return record

def analyze(report):
    summary = []
    start = -1
    content = ''
    for line in open(report):
        if start == -1:
            start = line.find('<record>')
            if -1 != start:
                content += line[start:]
            continue
        end = line.find('</record>')
        if -1 != end:
            content += line[0:end+len('</record>')]
            summary.append(get_record_info(content))
            content = ''
            start = -1
            continue
        content += line
    summary.sort(cmp=lambda x,y:cmp(int(y['count']), int(x['count'])))
    return summary

RE_SPF_PATTERN = re.compile(r'ip4:([a-zA-Z0-9\.-]+)/?(\d+)?')
def get_domain_spf_info(q, domain):
    ipranges = []
    spfinfo = q.dns_spf(domain)
    spfinfo = spfinfo.split()[1:] # drop the v=spf1
    for item in spfinfo:
        m = RE_SPF_PATTERN.search(item)
        if not m:
            continue
        ipranges.append([m.group(1), m.group(2) and int(m.group(2)) or 32])
    return ipranges

def ip2long(ip):
    return struct.unpack('!L', socket.inet_aton(ip))[0]

MASK = 0xFFFFFFFF
def in_iprange(ipranges, ip):
    ip = ip2long(ip)
    for _ip, _len in ipranges:
        if (~(MASK>>_len) & MASK & ip) == (~(MASK>>_len) & MASK & ip2long(_ip)):
            return True
    return False

def in_domain_spf(domain, ip):
    q = spf.query(i='127.0.0.1', s='localhost', h='unknown')
    return in_iprange(get_domain_spf_info(q, domain), ip)

# format:126.com!mail.meituan.com!1365436800!1365523199.xml
def parse_report_filename(report):
    parts = os.path.basename(report).split('.xml')[0].split('!')
    parts[2] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(parts[2])))
    parts[3] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(parts[3])))
    return tuple(parts)

RE_IPPATTERN = re.compile(r'^([0-9]{1,3}\.){4}$')
def invalid_ip(ip):
    return None == RE_IPPATTERN.match(ip+'.')

if __name__ == '__main__':
    if len(sys.argv) <= 2:
        print "usage:%s domain reportfile [reportfile2 ...]" % sys.argv[0]
        sys.exit()
    domain = sys.argv[1]
    q = spf.query(i='127.0.0.1', s='localhost', h='unknown')
    spf_ip_ranges = get_domain_spf_info(q, domain)
    for report in sys.argv[2:]:
        summary = {'fail': 0, 'domain.fail': 0, 'pass': 0, 'domain.pass': 0}
        for record in analyze(report):
            record['count'] = int(record['count'])
            ip = record['source_ip'].strip()
            if invalid_ip(ip):
                print >> sys.stderr, 'invalid ip from %s:%s' % (report, ip)
                continue
            ptr = q.dns_ptr(ip)
            fromdomain = in_iprange(spf_ip_ranges, ip) or domain in ' '.join(ptr)
            if 'pass' in (record['dkim'], record['spf']):
                summary['pass'] += record['count']
                if fromdomain:
                    summary['domain.pass'] += record['count']
            else:
                summary['fail'] += record['count']
                if fromdomain:
                    summary['domain.fail'] += record['count']
            # detail printer
            #print "%s: ptr=%s, %s=%s, count=%s, dkim=%s, spf=%s" % (ip, ptr, domain, fromdomain, record['count'], record['dkim'],record['spf'])
        print '%s->%s on %s-%s:' % parse_report_filename(report)
        print 'fail=%(fail)s, domain.fail=%(domain.fail)s, pass=%(pass)s, domain.pass=%(domain.pass)s\n' % summary 
