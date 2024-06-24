#!/usr/bin/python3

from OpenSSL import SSL, crypto
import socket
import certifi
import pem
import fnmatch
import logging
import requests
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)

# Cert Paths
TRUSTED_CERTS_PEM = certifi.where()

def get_cert_chain(target_domain):
    '''
    This function gets the certificate chain from the provided
    target domain. This will be a list of x509 certificate objects.
    '''
    dst = (target_domain.encode('utf-8'), 443)
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    s = socket.create_connection(dst)
    s = SSL.Connection(ctx, s)
    s.set_connect_state()
    s.set_tlsext_host_name(dst[0])

    s.sendall('HEAD / HTTP/1.0\n\n'.encode('utf-8'))
    s.recv(16)

    test_site_certs = s.get_peer_cert_chain()
    s.close()
    return test_site_certs

def get_sans(cert_chain):
    '''
    This function returns the Subject Alternative Names from the provided certificate chain.
    It also includes the CN in the list of SANs.
    '''
    dumpcert = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert_chain[-1]).decode('utf-8')
    logging.debug(dumpcert)
    sans = ''
    hit = 0
    for line in dumpcert.split('\n'):
        if hit == 1:
            sans = line
            break
        if 'X509v3 Subject Alternative Name:' in line:
            hit = 1
    sans = sans.split(', ')

    for i in range(len(sans)):
        sans[i] = sans[i].replace('DNS:', '')
        sans[i] = sans[i].replace(' ', '')

    if cert_chain[-1].get_subject().CN not in sans:
        sans.append(cert_chain[-1].get_subject().CN)

    return sans

def check_presence(target_domain, sans, cert_chain):
    '''
    This function checks if the target_domain is the subject or is present in the list of Subject Alternative Names.
    Furthermore, it also checks if the extra subdomain in the target_domain is a valid subdomain of the matched domain.
    '''
    matched_domain = ''
    for san in sans:
        if fnmatch.fnmatch(target_domain, san):
            matched_domain = san
            break

    logging.info(f'target_domain: {target_domain}')
    logging.info(f'matched_domain: {matched_domain}')

    if matched_domain == '':
        return False

    if matched_domain[0] == '*' and len(target_domain[:-(len(matched_domain)-1)].split('.')) >= 2:
        return False

    return True

def check_expiration(cert):
    '''
    Check if the certificate is within its valid date range.
    '''
    current_time = datetime.utcnow()
    if cert.has_expired():
        return False
    not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
    not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    return not_before <= current_time <= not_after

def x509_cert_chain_check(target_domain: str) -> bool:
    '''
    This function returns true if the target_domain provides a valid x509cert and false in case it doesn't or if there's an error.
    '''
    try:
        cert_chain = get_cert_chain(target_domain)
        store = crypto.X509Store()
        with open(TRUSTED_CERTS_PEM, 'rb') as f:
            trusted_certs = pem.parse(f.read())
            for cert in trusted_certs:
                store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, cert.as_bytes()))

        cert_chain.reverse()

        for cert in cert_chain:
            try:
                store_ctx = crypto.X509StoreContext(store, cert)
                store_ctx.verify_certificate()
                store.add_cert(cert)
            except crypto.X509StoreContextError as e:
                logging.error(f"Certificate verification error: {e}")
                return False

        for cert in cert_chain:
            if not check_expiration(cert):
                logging.error("Certificate has expired.")
                return False

        sans = get_sans(cert_chain)
        if not check_presence(target_domain, sans, cert_chain):
            logging.error("Domain not present in SANs.")
            return False

        logging.info("Certificate chain is valid.")
        return True

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return False

if __name__ == "__main__":
    print("Certificate Validator...")
    target_domain = input("Enter TLS site to validate: ")
    print("Certificate for {} verified: {}".format(target_domain, x509_cert_chain_check(target_domain)))
