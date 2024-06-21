#!/usr/bin/python3

from OpenSSL import SSL,crypto
import socket
import certifi
import pem
import fnmatch
import urllib

# Cert Paths
TRUSTED_CERTS_PEM = certifi.where()

def get_cert_chain(target_domain):
    '''
    This function gets the certificate chain from the provided
    target domain. This will be a list of x509 certificate objects.
    '''
    # Set up a TLS Connection
    dst = (target_domain.encode('utf-8'), 443)
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    s = socket.create_connection(dst)
    s = SSL.Connection(ctx, s)
    s.set_connect_state()
    s.set_tlsext_host_name(dst[0])

    # Send HTTP Req (initiates TLS Connection)
    s.sendall('HEAD / HTTP/1.0\n\n'.encode('utf-8'))
    s.recv(16)
    
    # Get Cert Meta Data from TLS connection
    test_site_certs = s.get_peer_cert_chain()
    s.close()
    return test_site_certs

############### Add Any Helper Functions Below

def get_sans(cert_chain):
    '''
    This function returns the Subject Alternative Names from the provided certificate chain. It also includes the CN in the list of sans.
    '''

    # We get the dump of the last certificate in the chain.
    # Why the last certificate? Because the last certificate is the leaf certificate. This certificate is the one that is issued directly to the domain and contains the SANs.
    dumpcert = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert_chain[-1]).decode('utf-8')
    # print(dumpcert)
    sans = ''
    hit = 0
    for line in dumpcert.split('\n'):
        if hit == 1:
            sans = line
            break
        if 'X509v3 Subject Alternative Name:' in line:
            hit = 1
    sans = sans.split(', ')

    # We remove 'DNS:' and extra space from elements in the list, if present.
    for i in range(len(sans)):
        sans[i] = sans[i].replace('DNS:', '')
        sans[i] = sans[i].replace(' ', '')

    # We add the CN to the list of sans if it is not already present.
    if cert_chain[-1].get_subject().CN not in sans:
        sans.append(cert_chain[-1].get_subject().CN)

    return sans


def check_presence(target_domain, sans, cert_chain):
    '''
    This function checks if the target_domain is the subject or is present in list of Subject Alternative Names. Furthermore, it also checks if the extra subdomain in the target_domain is a valid subdomain of the matched domain.
    '''

    # We check if the target_domain is the subject or is present in the list of SANs.
    matched_domain = ''
    for san in sans:
        if fnmatch.fnmatch(target_domain, san):
            matched_domain = san
            break
    print('-----------------------')
    print('target_domain: ', target_domain)
    print('matched_domain: ', matched_domain)

    # If the target_domain is not the CN or is not present in the list of SANs, we return False.
    if matched_domain == '':
        print('-----------------------')
        return False
    
    # If the matched_domain is a wildcard domain, we check if the target_domain has a valid subdomain of the matched_domain for the * case.
    if matched_domain[0] == '*' and len(target_domain[:-(len(matched_domain)-1)].split('.')) >= 2:
        print(target_domain[:-(len(matched_domain)-1)].split('.'))
        print('-----------------------')
        return False
    print('-----------------------')
    return True


##############################################

def x509_cert_chain_check(target_domain: str) -> bool:
    '''
    This function returns true if the target_domain provides a valid x509cert and false in case it doesn't or if there's an error.
    '''
    # TODO: Complete Me!

    # We get the certificate chain for the target_domain.
    cert_chain = get_cert_chain(target_domain)

    # We create a store and add the trusted certificates to it.
    store = crypto.X509Store()
    with open(TRUSTED_CERTS_PEM, 'rb') as f:
        trusted_certs = pem.parse(f.read())
        for cert in trusted_certs:
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, cert.as_bytes()))

    # We reverse the certificate chain. Now the Root CA certificate is the first certificate in the chain and the leaf certificate is the last certificate in the chain.
    cert_chain.reverse()

    # We verify the certificate chain iteratively, insired from the Youtube Video's methodology. There they had just one intermediate certificate, here, we extend that idea such that we can accomodate multiple intermediate certificate. Verification is done iteratively from the root to the leaf, and the certificates are added to the store only if they are verified.
    for cert in cert_chain:
        try:
            store_ctx = crypto.X509StoreContext(store, cert)
            store_ctx.verify_certificate()
            store.add_cert(cert)
        except Exception as e:
            # If the certificate is not verified, we directly return False.
            return False

    # We get the list of Subject Alternative Names(with the CN) from the certificate chain. Why did I take all sans from leaf certificate and not just the CN? Because the domain might be present in the SANs and not in the CN.
    sans = get_sans(cert_chain)

    # Last check to see if the target_domain is indeed in the CN or is present in the list of Subject Alternative Names.
    check = check_presence(target_domain, sans, cert_chain)

    return check


if __name__ == "__main__":
    
    # Standalone running to help you test your program
    print("Certificate Validator...")
    target_domain = input("Enter TLS site to validate: ")
    print("Certificate for {} verifed: {}".format(target_domain, x509_cert_chain_check(target_domain)))
