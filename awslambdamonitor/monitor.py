import boto3
import requests
import requests.exceptions
import logging
import yaml
import sys
import re
import signal

# sudo yum install libffi-devel gcc python-devel openssl-devel
from OpenSSL import SSL

# sudo pip install ndg-httpsclient # http://stackoverflow.com/a/18579484/168874
#from botocore.vendored.requests.packages.urllib3.contrib.pyopenssl import OpenSSL
#from OpenSSL import SSL

# sudo pip install paramiko ecdsa pycrypto
import paramiko

# sudo pip install python-whois
from whois import whois

import socket
from datetime import datetime
from ftplib import FTP

# sudo pip install python-dateutil
from dateutil import tz

TIME_ZONE = tz.gettz('America/Los_Angeles')

# http://bradconte.com/using-load_verify_locations
CA_CERTS = "/etc/ssl/certs/ca-bundle.crt"


def pst_time(secs):
    from_zone = tz.gettz('UTC')
    to_zone = TIME_ZONE
    utc = datetime.fromtimestamp(secs)
    utc = utc.replace(tzinfo=from_zone)
    pst = utc.astimezone(to_zone)
    return pst.timetuple()

logger = logging.getLogger(__name__)
if len(logging.getLogger().handlers) == 0:
    logger.addHandler(logging.StreamHandler())
logging.getLogger().setLevel(logging.INFO)
# fmt = "[%(levelname)s]   %(asctime)s.%(msecs)dZ  %(aws_request_id)s  %(message)s"
fmt = "[%(levelname)s] %(asctime)s %(message)s\n"
# datefmt = "%Y-%m-%dT%H:%M:%S"
datefmt = "%m/%d/%Y %H:%M:%S {}".format(TIME_ZONE.tzname(datetime.now()))
formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)
formatter.converter = pst_time
logging.getLogger().handlers[0].setFormatter(formatter)


# Disable boto logging
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)

CONFIG = '''---
vars:
  sns_topic_arn: arn:aws:sns:us-west-2:123456789012:LambdaAlerts
  sns_region: us-west-2
  cert_expiration_days_threshold: 14
  domain_expiration_days_threshold: 14
  ftp_timeout: 2
  alert: true
schedules:
  AWSLambdaMonitor5Minutes:
    host1.example.com:
    - category: http
      url: http://www.host1.example.com/
      substring: My example substring
    host2.example.com:
    - category: port
      port: 22
    - category: dns
      hostname: foo.host2.example.com
      ip: 203.0.113.100
  AWSLambdaMonitorDaily:
    host1.example.com:
    - category: certificate_age
    example.org:
    - category: domain_expiration
  AWSLambdaMonitorFailureTest:
    google.com:
    - category: http
      url: http://www.google.com/?source=awslambdamonitor
      substring: A substring not present on the page
    - category: http
      url: http://www.google.com/?source=awslambdamonitor
      regex: A .* not present on the page
    - category: dns
      hostname: google.com
      ip: 1.2.3.4
    expired.badssl.com:
    - category: certificate_age
    persona.org:
    - category: ftp
'''


class Events:

    def __init__(self):
        self.events = []

    def create(self, success, name, host, category, data):
        event = {"success": success,
                 "name": name,
                 "host": host,
                 "category": category,
                 "data": data}
        self.events.append(event)
        log(event, success)

    def get_failures(self):
        return [x for x in self.events if not x['success']]

    def get_events(self):
        return self.events


class TimeoutError(Exception):
    pass


class Timeout:

    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, exception_type, exception_value, traceback):
        del exception_type, exception_value, traceback
        signal.alarm(0)


def log(event, success):
    msg = "{host} : {category} : {success} : {name} : {data}".format(
        **event)
    logger.log(logging.INFO if success else logging.ERROR, msg)


def check_expiration_date(asn1, name, threshold):
    """
    Check a certificate expiration date in ASN.1 GENERALIZEDTIME format to
    determine if has already expired or will expire soon. Return a 3-tuple
    of success, dns name, and message.

    :param asn1: ASN.1 GENERALIZEDTIME format string
    :param name: DNS name
    :param threshold: Number of days remaining before expiration under which a
           problem is called out
    :return: 3-tuple of (success, name, message)
        success: Boolean value indicating if there is a problem or not
        name: DNS name
        message: String describing the status
    """
    date_format = "%Y%m%d%H%M%SZ"
    try:
        expire_date = datetime.strptime(asn1, date_format)
    except ValueError:
        return (False,
                name,
                'Certificate date of %s does not match expected format'
                ' of %s' % (asn1, date_format))

    expire_in = expire_date - datetime.now()
    logger.debug("Certificate %s will expire in %s days on %s" %
                 (name, expire_in.days, asn1))
    if expire_in.days <= 0:
        return (False,
                name,
                'Certificate %s has expired as of %s'
                % (name, asn1))
    elif expire_in.days <= threshold:
        return (False,
                name,
                'Certificate %s will expire in %s days'
                % (name, expire_in.days))
    else:
        return (True,
                name,
                "Certificate %s won't expire for %s days"
                % (name, expire_in.days))


def http(config, host, url, regex=None, substring=None):
    """
    Check a URL

    :param config: Unused
    :param host: Unused
    :param url: The URL to be fetched
    :param regex: The regular expression to search the response for
    :param substring: The string to search the response for
    :return: 3-tuple of (success, name, message)
        success: Boolean value indicating if there is a problem or not
        name: DNS name
        message: String describing the status
    """
    del config, host
    name = url
    timeout = 15
    try:
        r = requests.get(url, timeout=timeout)
        if (regex is not None) and (substring is not None):
            raise Exception("You can't define a regex and a strcmp value")
        if regex is not None:
            logger.debug("Checking for regex %s" % regex)
            result = re.search(regex, r.text)
            return (
                result is not None,
                name,
                'Response in %4.3f seconds. Regex "%s" %s' %
                (r.elapsed.total_seconds(), regex,
                 'matched' if result is not None else 'not found'))
        if substring is not None:
            return (substring in r.text,
                    name,
                    'Response in %4.3f seconds. Substring "%s" %s' %
                    (r.elapsed.total_seconds(), substring,
                     'found' if substring in r.text else 'not found'))
    except requests.exceptions.ConnectionError as e:
        if 'timed out' in repr(e.message):
            return (False, name, "Request timed out after %s seconds. %s" %
                    (timeout, e))
        else:
            return (False, name,
                    "Non time-out Exception %s %s : message '%s' and the "
                    "type of e.message is %s" %
                    (e.__class__, e, e.message, type(e.message)))
    except requests.exceptions.Timeout as e:
        return (False, name, "Request timed out after %s seconds. %s" %
                (timeout, e))
    except requests.exceptions.RequestException as e:
        return False, name, "Request error %s %s" % (e.__class__, e)
    except TimeoutError:
        raise
    except Exception as e:
        return False, name, "Exception %s %s" % (e.__class__, e)
    return (r.ok, name, 'Response in %4.3f seconds. %s' %
            (r.elapsed.total_seconds(), r.reason))


def certificate_age(config, host):
    """
    Check a TLS certificate of a host to determine if it's going to expire soon

    :param config: dictionary containing settings
        config['vars']['cert_expiration_days_threshold']: If the certificate
        is set to expire in a number of days less than this threshold then
        alert
    :param host: The host to fetch the certificate from
    :return: 3-tuple of (success, name, message)
        success: Boolean value indicating if there is a problem or not
        name: DNS name
        message: String describing the status
    """
    name = host
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, 443))
    except Exception as e:
        return False, name, "Exception %s %s" % (e.__class__, e)
    try:
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.load_verify_locations(CA_CERTS)
    except Exception as e:
        return False, name, "Exception %s %s" % (e.__class__, e)

    try:
        ssl_sock = SSL.Connection(ctx, sock)
        ssl_sock.set_connect_state()
        ssl_sock.set_tlsext_host_name(host)
        ssl_sock.do_handshake()

        x509 = ssl_sock.get_peer_certificate()
        asn1 = x509.get_notAfter()
        result = check_expiration_date(
            asn1,
            name,
            config['vars']['cert_expiration_days_threshold'])
    except Exception as e:
        return False, name, "Exception %s %s" % (e.__class__, e)
    finally:
        ssl_sock.shutdown()

    sock.close()
    return result


def ftp(config, host):
    """
    Check a hosts FTP service

    :param config: dictionary containing settings
        config['vars']['ftp_timeout']: The timeout in seconds to wait for the
        ftp connection to complete by
    :param host: The host to connect to over FTP
    :return: 3-tuple of (success, name, message)
        success: Boolean value indicating if there is a problem or not
        name: DNS name
        message: String describing the status
    """
    name = host
    try:
        ftp_conn = FTP(host=host,
                       timeout=config['vars']['ftp_timeout'])
    except Exception as e:
        return False, name, "Exception %s %s" % (e.__class__, e)
    welcome = ftp_conn.getwelcome()
    ftp_conn.quit()
    return True, name, "FTP ok %s" % welcome


def dns(config, host, hostname, ip):
    """
    Check that a DNS name resolves to the expected IP

    :param config: Unused
    :param host: Unused
    :param hostname: The DNS name to check
    :param ip: The IP address which the hostname should resolve to
    :return: 3-tuple of (success, name, message)
        success: Boolean value indicating if there is a problem or not
        name: DNS name
        message: String describing the status
    """
    del config, host
    name = hostname
    try:
        resolved_ips = [x[4][0] for x in socket.getaddrinfo(hostname, 80)]
    except Exception as e:
        return (False, name, "Unable to resolve %s : %s %s"
                % (hostname, e.__class__, e))
    if ip not in resolved_ips:
        return (False, name, "Expected IP of %s for name %s was not found in "
                "the actual resolved IPs of %s" % (ip, hostname, resolved_ips))
    else:
        return True, name, "%s resolves to %s" % (hostname, resolved_ips)


def port(config, host, port_num):
    """
    Check that a host is listening on a port

    :param config: Unused
    :param host: The host to connect to
    :param port_num: The port to check
    :return: 3-tuple of (success, name, message)
        success: Boolean value indicating if there is a problem or not
        name: DNS name
        message: String describing the status
    """
    del config
    name = "%s:%s" % (host, port_num)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, port_num))
    if result == 0:
        return True, name, "Connected to port %s on %s" % (port_num, host)
    else:
        return (False, name, "Unable to connect to port %s on %s"
                % (port_num, host))


def ssh(config, host):
    """
    Check that a host is running SSH

    :param config: Unused
    :param host: The host to check
    :return: 3-tuple of (success, name, message)
        success: Boolean value indicating if there is a problem or not
        name: DNS name
        message: String describing the status
    """
    del config
    name = host
    try:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(
            paramiko.client.MissingHostKeyPolicy())
        ssh_conn.connect(host)
        return True
    except (paramiko.BadHostKeyException, paramiko.AuthenticationException,
            paramiko.SSHException, socket.error) as e:
        return (False, name, "Unable to SSH to %s %s %s"
                % (host, e.__class__, e))


def email_delivery(config, host):
    """
    Stub for future end to end email test

    :param config:
    :param host:
    :return:
    """
    del config, host
    return True


def domain_expiration(config, host):
    """
    Check if a domain name is going to expire soon

    :param config: dictionary containing settings
        config['vars']['domain_expiration_days_threshold']: If the domain name
        is set to expire in a number of days less than this threshold then
        alert
    :param host: The domain name to check
    :return: 3-tuple of (success, name, message)
        success: Boolean value indicating if there is a problem or not
        name: DNS name
        message: String describing the status
    """
    name = host
    result = whois(host)
    logger.debug("Domain %s expires on %s" % (host, result.expiration_date))
    expiration_date = result.expiration_date[0] if type(
        result.expiration_date) == list else result.expiration_date
    expire_in = expiration_date - datetime.now()
    logger.debug("Certificate %s will expire in %s days" %
                 (host, expire_in.days))
    if expire_in.days <= 0:
        return (False, name, "Domain %s expired %s days ago"
                % (host, expire_in.days * -1))
    elif expire_in.days <= config['vars']['domain_expiration_days_threshold']:
        return (False, name, "Domain %s will expire in %s days"
                % (host, expire_in.days))
    else:
        return (True, name, "Domain %s won't expire for %s days"
                % (host, expire_in.days))


def alert(events, region, topic_arn, log_stream):
    """
    Publish an alert to SNS

    :param events: Either a string containing an event message or a list of
    strings for multiple event messages
    :param region: The AWS region containing the SNS topic
    :param topic_arn: The AWS SNS topic ARN
    :param log_stream: The AWS CloudWatch Log Stream
    :return: Dictionary containing the MessageId of the published SNS message
    """
    message = ''
    logger.error('Alerting on events %s' % events)
    if type(events) == list:
        for event in events:
            message += ("{host} : {category} : {success} : {name} : {data}"
                        "\n".format(**event))
    else:
        message += str(events) + "\n"
    message += "Log stream is : %s" % log_stream
    subject = 'Alert : AWS Lambda Monitor detected events'
    client = boto3.client('sns', region_name=region)
    return client.publish(
        TopicArn=topic_arn,
        Message=message,
        Subject=subject,
    )


def get_event_type(event):
    """
    Determine where an event originated from based on it's contents

    :param event: A dictionary of metadata for an event
    :return: Either the name of the source of the event or False if no
    source can be determined
    """
    if 'source' in event and event['source'] == 'aws.events':
        # CloudWatch Scheduled Event
        return 'cloudwatch'
    elif ('Records' in event and
          type(event['Records']) == list and
          len(event['Records']) > 0 and
          type(event['Records'][0]) == dict and
          'eventSource' in event['Records'][0] and
          event['Records'][0]['eventSource'] == 'aws:ses'):
        # SES received email
        return 'ses'
    else:
        return False


def get_rules(event, event_type):
    """
    Determine the rules to check from the event metadata. A rule is a
    collection of hosts and associated checks

    :param event:  A dictionary of metadata for an event
    :param event_type: The type of event based on the source that created it
    :return: A list of rules
    """
    if event_type == 'cloudwatch':
        # CloudWatch Scheduled Event
        if 'resources' in event and type(event['resources']) == list:
            logger.debug("Resources = %s" % event['resources'])
            prog = re.compile('arn:aws:events:[^:]*:[^:]*:rule/(.*)')
            return [prog.match(x).group(1)
                    for x in event['resources']
                    if prog.match(x) is not None]
    elif event_type == 'ses':
        # SES received email
        rules = []
        prog = re.compile('AWSLambdaMonitor\S*')
        for record in event['Records']:
            words = record['ses']['mail']['commonHeaders']['subject'].split()
            for word in words:
                match = prog.match(word)
                if match is not None:
                    rules.append(match.string)
        return rules
    else:
        return []


def monitor(event, context):
    """
    Given an event dictionary, determine the rules to monitor and iterate
    through all hosts and checks for that rule, running each check. Gather
    up the results and alert on them.

    :param event: A dictionary of metadata for an event
    :param context: The AWS Lambda context object
    :return: A list of checks which resulted in failures
    """
    timeout = 110
    timeout_reached = False
    events = Events()
    with open('monitor.yaml') as f:
        config = yaml.load(f.read())
    try:
        with Timeout(seconds=timeout):

            event_type = get_event_type(event)
            rules = get_rules(event, event_type)

            logger.debug("Rules = %s" % rules)

            for rule in rules:
                logger.debug("Rule = %s and config['schedules'] keys = %s" % (
                    rules, config['schedules'].keys()))
                if rule not in config['schedules'].keys():
                    continue
                for hostname in config['schedules'][rule].keys():
                    for host in config['schedules'][rule][hostname]:
                        category = host['category']
                        host['config'] = config
                        del host['category']
                        result = getattr(sys.modules[__name__], category)(
                            host=hostname, **host)
                        events.create(result[0],
                                      result[1],
                                      hostname,
                                      category,
                                      result[2])
    except TimeoutError:
        events.create(False,
                      'Timeout',
                      'Timeout',
                      'Timeout', "Timeout %s reached" % timeout)
        timeout_reached = True
    except Exception as e:
        alert("Uncaught exception thrown %s %s" % (e.__class__, e),
              config['vars']['sns_region'],
              config['vars']['sns_topic_arn'],
              context.log_stream_name)
        raise

    if timeout_reached or event_type == 'ses':
        alert(events.get_events(),
              config['vars']['sns_region'],
              config['vars']['sns_topic_arn'],
              context.log_stream_name)
    elif (len(events.get_failures()) > 0 and
          'alert' in config['vars'] and
          config['vars']['alert']):
        alert(events.get_failures(),
              config['vars']['sns_region'],
              config['vars']['sns_topic_arn'],
              context.log_stream_name)
    return events.get_failures()


def main():
    """
    Run monitor for two example rules

    :return:
    """
    event = {
        'resources':
        ['arn:aws:events:us-west-2:123456789123:rule/AWSLambdaMonitor5Minutes',
         'arn:aws:events:us-west-2:123456789123:rule/AWSLambdaMonitorDaily']}
    context = type('context', (), {'log_stream_name': None})()
    result = monitor(event, context)
    print(result)

if __name__ == '__main__':
    main()
