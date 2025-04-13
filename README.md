# AT&T BGW Certificate Extractor
This tool is designed to extract the device certificates and key material needed for 802.1x auth on AT&T's fiber network from files found on the provided gateway. For the most part, this is pointless except on GPON (making the BGW620-700 nothing more than a curiosity for now as only XGSPON customers can get one).

The device-unique certificates are stored on flash with the private key encrypted. Each device family has a hardcoded AES key/IV in `/bin/eap_tls_peer` that can be used to decrypt the private key material stored on flash. For the BGW210 and BGW320 there are firmwares available with unencrypted rootfs images. For the BGW620 all published firmwares discovered to date are encrypted, meaning that even with a full flash dump the private key was unrecoverable.

With this tool BGW620-700 certificates are recoverable as long as you can get a flash dump from a device.

## Requirements
- Python 3.7+
- pycryptodome

## Usage
- `pip install pycryptodome`
- `./extract_bgw_certs.py your_calibration_01.bin output_eapol.tgz`

You will need to modify the `wpa_supplicant.conf` with updated file paths; should be self-explanatory.

For the BGW210-700 pass `mfg.dat` instead of `calibration_01.bin`. For all other devices pass `calibration_01.bin`.

## Devices Supported
- BGW210-700
	- [Obtaining input files](https://github.com/0x888e/certs)
- BGW320-500
	- [Obtaining input files](https://github.com/0x888e/certs)
- BGW320-505
	- [Obtaining input files](https://github.com/0x888e/certs)
- BGW620-700
	- No published method to extract via software
	- Obtaining, at present, requires either undisclosed software access or lifting the flash and pulling it from the mfg partition manually

## Credits
Authored by rss (@rssor) and d (@slush0_) from 8311

## Resources
- [mfgdat](https://github.com/abrender/mfgdat/) open-source Go/Bash implementation filling a similar niche
- [mfg_dat_decode](https://www.devicelocksmith.com/2018/12/eap-tls-credentials-decoder-for-nvg-and.html) the original closed-source implementation from devicelocksmith, with support for all but the BGW620-700
- [0x888e/certs](https://github.com/0x888e/certs) software-only method to get the necessary files out of a BGW210 or BGW320
