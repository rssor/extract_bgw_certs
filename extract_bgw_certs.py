#!/usr/bin/env python3
# Authors: rss (@rssor) and d (@slush0_) of 8311
import base64
import re
import struct
import tarfile
from io import BytesIO

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SUPPLICANT_CONF = b"""ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=wheel
openssl_ciphers=DEFAULT@SECLEVEL=0
eapol_version=2
ap_scan=0
network={
        ca_cert="/FULL/PATH/TO/ca.pem"
        client_cert="/FULL/PATH/TO/client.der"
        private_key="/FULL/PATH/TO/privatekey.der"
        eap=TLS
        eapol_flags=0

        # identity must be the mac address of the interface
        # wpa_supplicant is running on. it doesn't seem to
        # have to actually match the mac in the interface.
        # you either need to change your wan mac address to
        # match this one OR change this to match your wan
        # mac address.
        identity="MAC_ADDRESS"
        key_mgmt=IEEE8021X
        phase1="allow_canned_success=1"
}
"""

ATT_ROOT = b"""-----BEGIN CERTIFICATE-----
MIIDjTCCAnWgAwIBAgIQaZZlNVfAj8C+PAyFWjR9TTANBgkqhkiG9w0BAQUFADBL
MQswCQYDVQQGEwJVUzEZMBcGA1UEChMQQVRUIFNlcnZpY2VzIEluYzEhMB8GA1UE
AxMYQVRUIFNlcnZpY2VzIEluYyBSb290IENBMB4XDTExMDIyNDAwMDAwMFoXDTMx
MDIyMzIzNTk1OVowSzELMAkGA1UEBhMCVVMxGTAXBgNVBAoTEEFUVCBTZXJ2aWNl
cyBJbmMxITAfBgNVBAMTGEFUVCBTZXJ2aWNlcyBJbmMgUm9vdCBDQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAPecTeoY88yWw8n8tjxSuhNGYvTeS6/J
vCmG5GEUwmqOrPwQp+dyuDQ6U5kXZAI43XTvEWBhqRvGk858JmvQm0fw/mj4l4fN
KzcEUSAEyKMuYSqaNavPEFRUGMcWx+lHC1ZDgrehVhRCdvGmTkOm5FC0QU2NBXDL
Hl9XswadhBH7KN5n673qgVaziazRt4m009wsbU2IlGq3duqReLJRmurdo1bT6AhK
PPLCOm5c956IhVNsuKy1rclNHvqR8XQH1slzDoQ2+bBXNxZGMFgEquLaraZodsWV
/HF9/1LOojb0BDa0nhvSCQ6vHhW1YSkkM3rLKX3ySkxyGnek4w/rOwkCAwEAAaNt
MGswEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwJgYDVR0RBB8w
HaQbMBkxFzAVBgNVBAMTDk1QS0ktMjA0OC0xLTkyMB0GA1UdDgQWBBSXIJnCcypF
6+ACf0fae6t86x+vbjANBgkqhkiG9w0BAQUFAAOCAQEAq/zvYiIjZgYvpgRL4oUi
CaYqHWrWSYHG+k0zRGw1ysu4MxsaHY3JMQmF7E0OoBPsLuxfOvVxUCRrO0CFyBtJ
3s49FhLtRTrQGs/7DoL+tL80pIsgH7EX9a4koD/fjuCZe1dr9JsHqI0SUblfy5CX
s6BnhoXTJYAa47RhJwqMJ8jMRsUEKWPBDc13EGH6+w3Sw2CMvvWuriKSFicLlmLc
OrIPBwSwELYAd82Vm7HQO2HbHO/hp+VewqZiXWErWjWr+D0ScfNR82gwkaDPwZUZ
Tju8Z+QyAsLMtdBtFBoRtWs4kJLQWvXbILTpICxl8dYQFZ7Sv4dxdl2GdsNNtSSo
xw==
-----END CERTIFICATE-----"""

def aes_key_material_decode(key, sub):
    key = bytes.fromhex(key)
    output = bytearray(17)
    output[0] = sub

    for i, b in enumerate(key):
        output[i + 1] = (b - output[i]) & 0xFF

    return bytes(output[1:])

# these keys are recovered from /bin/eap_tls_peer on the devices
# in question. the keys used for the obfuscation are _themselves_
# obfuscated through use of a simple byte-to-byte subtraction with
# a seed. these key/iv values are the values that can be found
# in .data in eap_tls_peer to validate
#
# obtaining eap_tls_peer:
#  BGW210: firmwares never encrypted, any will do
#  BGW320: you'll want 3.17 or earlier; 3.18+ have encrypted rootfs
#  BGW620: get code execution first; rootfs is encrypted
private_key_obfuscation_keys = {
    "BGW620-700": ( # Vantiva (formerly CommScope (formerly Arris))
        ("e44fc71dbb25a4425df7ac3dc539a0e8", 0x3B),
        ("5ecf98c9da82e7dbe1e7860f2e848717", 0xDB),
        0,
        lambda plaintext: unpad(plaintext, 16),
    ),
    "BGW320-505": ( # Nokia
        ("9143b7eae9d605e24de755e25132ec76", 0x9C),
        ("6fcabb3c436a053db858cd81810d26d1", 0x65),
        0,
        lambda plaintext: unpad(plaintext, 16),
    ),
    "BGW320-500": ( # Humax
        ("e6a416fec4dce1957593965a38ea3081", 0x8A),
        ("900a0b806c3251c2c15eb53e56477373", 0x0F),
        0,
        lambda plaintext: unpad(plaintext, 16),
    ),
    "BGW210-700": ( # Arris
        ("ac8ee680f10f9f51b7303707c04c1775", 0x20),
        ("4fa84deb514f73990b49572acdf20ed9", 0x20),
        8,
        lambda plaintext: plaintext,
    ),
}


def attempt_decrypt(contents):
    for model, key_material in private_key_obfuscation_keys.items():
        key = aes_key_material_decode(*key_material[0])
        iv = aes_key_material_decode(*key_material[1])

        aes = AES.new(key, AES.MODE_CBC, iv)
        try:
            plaintext = aes.decrypt(contents[key_material[2]:])

            # primitive DER check -- strictly speaking
            # this has a 1 in 65,536 chance of accepting
            # bad data as a BGW210 cert
            if not plaintext.startswith(b"\x30\x82"):
                continue

            # attempt to unpad before printing success to
            # filter out any chance of bad identification
            # of a BGW320/BGW620
            plain = key_material[3](plaintext)

            print(f"[+] Private key from {model} detected")
            return plain
        except Exception:
            continue

    return None


def wrap_cert(cert):
    cert = base64.b64encode(cert)
    lines = []
    while cert:
        lines.append(cert[:64])
        cert = cert[64:]
    return (
        b"-----BEGIN CERTIFICATE-----\n"
        + b"\n".join(lines)
        + b"\n-----END CERTIFICATE-----"
    )


# Not totally sure about this, works for my n=1
TYPES = {
    4: "Private Key",
    2: "Client Cert",
    3: "CA Cert",
}


def create_config_from_calibration(calibration, output_conf):
    (magic1, magic2, size, count) = struct.unpack_from(">IIII", calibration)
    contents_start = 0x14 + (count * 0x10)

    assert magic1 == 0x0E0C0A08
    assert magic2 == 0x02040607
    assert size <= len(calibration)

    items = {}
    for i in range(count):
        (start, size, kind, flags) = struct.unpack_from(">IIII", calibration, 0x14 + (i * 0x10))
        raw = calibration[contents_start + start : contents_start + start + size]

        print(f"[+] Found: {TYPES[kind]} (start: {start}, size: {size}, flags: {flags})")

        if flags & 1:
            raw = attempt_decrypt(raw)
        items.setdefault(kind, []).append(raw)

    ca_certs = list(map(wrap_cert, items[3]))
    ca_certs.append(ATT_ROOT)

    conf = SUPPLICANT_CONF
    if mac := re.search((b"[0-9a-fA-F]{2}:" * 6)[:-1], items[2][0]):
        conf = conf.replace(b"MAC_ADDRESS", mac.group())
    else:
        print("[!] Unable to recover MAC address from client certificate")

    with tarfile.open(mode="w:gz", fileobj=output_conf) as tar:

        def add(tar, name, data):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, BytesIO(data))

        add(tar, "eapol/wpa_supplicant.conf", conf)
        add(tar, "eapol/client.der", items[2][0])
        add(tar, "eapol/privatekey.der", items[4][0])
        add(tar, "eapol/ca.pem", b"\n".join(ca_certs))


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()

    p.add_argument(
        "calibration_or_mfgdat",
        type=argparse.FileType("rb"),
        help="The output filename for the calibration_01.bin file extracted from the device",
    )
    p.add_argument(
        "eapol_tar",
        type=argparse.FileType("wb"),
        help="The output filename for the gzipped tar package containing eapol config files",
    )
    args = p.parse_args()

    # consume at most the last 16KiB -- on the BGW210 the data we
    # want is located exactly 16KiB from the of mfg.dat, but this
    # data was split off into calibration_01.bin on the BGW320
    # and BGW620.
    calibration_data = args.calibration_or_mfgdat.read()[-0x4000:]

    create_config_from_calibration(calibration_data, args.eapol_tar)
    print(f"[+] Wrote eapol config files to {args.eapol_tar.name}")
