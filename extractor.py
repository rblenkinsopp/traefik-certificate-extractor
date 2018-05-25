import sys
import os
import errno
import time
import json
import logging
from base64 import b64decode

import pem
from OpenSSL import crypto
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def extract_certificates_from_acme(acme_file):
    # Read JSON file
    data = json.loads(open(acme_file).read())
    certs = data['Certificates']

    # Loop over all certificates
    for c in certs:
        # Decode private key, certificate and chain
        privatekey = b64decode(c['Key']).decode('utf-8')
        fullchain = b64decode(c['Certificate']).decode('utf-8')
        start = fullchain.find('-----BEGIN CERTIFICATE-----', 1)
        cert = fullchain[0:start]
        chain = fullchain[start:]

        # Create PKCS#12 certificate archive
        pkcs12 = crypto.PKCS12()
        pkcs12.set_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, privatekey))
        pkcs12.set_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, cert))
        ca_certs = [crypto.load_certificate(crypto.FILETYPE_PEM, c.as_bytes()) for c in pem.parse(bytes(chain, encoding='utf-8'))]
        pkcs12.set_ca_certificates(ca_certs)
        pfx = pkcs12.export()

        # Create domain directory if it doesn't exist
        directory = 'certs/' + c['Domain']['Main'] + '/'
        try:
            os.makedirs(directory)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise

        # Write private key, certificate and chain to file
        with open(directory + 'privkey.pem', 'w') as f:
            f.write(privatekey)
        with open(directory + 'cert.pem', 'w') as f:
            f.write(cert)
        with open(directory + 'chain.pem', 'w') as f:
            f.write(chain)
        with open(directory + 'fullchain.pem', 'w') as f:
            f.write(fullchain)
            with open(directory + 'cert.pfx', 'wb') as f:
                f.write(pfx)

        # Write private key, certificate and chain to flat files
        directory = 'certs_flat/'

        with open(directory + c['Domain']['Main'] + '.key', 'w') as f:
            f.write(privatekey)
        with open(directory + c['Domain'] ['Main']+ '.crt', 'w') as f:
            f.write(fullchain)
        with open(directory + c['Domain']['Main'] + '.chain.pem', 'w') as f:
            f.write(chain)
        with open(directory + c['Domain']['Main'] + '.pfx', 'wb') as f:
            f.write(pfx)

        if c['Domain']['SANs']:
            for name in c['Domain']['SANs']:
                with open(directory + name + '.key', 'w') as f:
                    f.write(privatekey)
                with open(directory + name + '.crt', 'w') as f:
                    f.write(fullchain)
                with open(directory + name + '.chain.pem', 'w') as f:
                    f.write(chain)
                with open(directory + name + '.pfx', 'wb') as f:
                    f.write(pfx)

        print('Extracted certificate for: ' + c['Domain']['Main'] + (', ' + ', '.join(c['Domain']['SANs']) if c['Domain']['SANs'] else ''))


class AcmeFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        self.handle(event)

    def on_modified(self, event):
        self.handle(event)

    def handle(self, event):
        # Check if it's a JSON file
        if not event.is_directory and event.src_path.endswith('acme.json'):
            logging.info('Certificates changed')
            extract_certificates_from_acme(event.src_path)

if __name__ == "__main__":
    # Determine path to watch
    path = sys.argv[1] if len(sys.argv) > 1 else './data'

    # Create output directories if it doesn't exist
    try:
        os.makedirs('certs')
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise
    try:
        os.makedirs('certs_flat')
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise

    # Load existing file if present
    acme_file_path = os.path.join(path, "acme.json")
    if os.path.isfile(acme_file_path):
        logging.info("Loading initial file {}".format(acme_file_path))
        extract_certificates_from_acme(acme_file_path)

    # Create event handler and observer
    event_handler = AcmeFileHandler()
    observer = Observer()

    # Register the directory to watch
    observer.schedule(event_handler, path)

    # Main loop to watch the directory
    observer.start()
    logging.info("Watching {} for certificate updates".format(path))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
