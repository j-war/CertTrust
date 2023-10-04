# CertTrust
Update based on [ADVTrustStore](https://github.com/ADVTOOLS/ADVTrustStore).

- Updated to use _**Python3**_ and [ASN1.py 2.6.0](https://pypi.org/project/asn1/).
- Tested on Xcode 14.2 and iOS 16.x.

Note:
- Only the two happy paths below were tested, there are likely python conversion errors remaining.
- Adding a cert with this script after having used the old version will likely silently fail due to sha1/sha256/hash changes. Re-create your TrustStore.sqlite3 and try again. Delete TrustStore.sqlite3 from the simulator, close and reopen the simulator.
- Will handle certificates saved with CRLF and LF endings as well as some missing fields.

### Known limitations and caveats:
- Certificates without a CN may not show in Certificate Trust Settings but "Enable Full Trsut For Root Certificates" will appear. developer.apple.com/forums/thread/89568
- Some certificates are not automatically toggled.
- The TrustStore file is created after after a simulator has been started for the first time so this script will need to be run afterwards.
- You may need to close and reopen the simulator after running the script.

## Usage:

1. Add this as a build phase script to Xcode:
```
#!/bin/zsh
if which python3 > /dev/null; then
  python3 $SRCROOT/scripts/CertTrust.py -a $SRCROOT/scripts/CERTIFICATE.cer -y
else
  echo "warning: Python3 not installed"
fi
```
3. Add certificate to a specific simulator:

```
python3 CertTrust.py -a CERTIFICATE.cer -t path/to/TrustStore.sqlite3 -y
```

3. Add certificate to all simulators:

```
python3 CertTrust.py -a CERTIFICATE.cer -y
```
