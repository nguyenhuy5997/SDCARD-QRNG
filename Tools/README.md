# Tools for the V8Y board (CA provisioning, status)

| File | What |
|---|---|
| `ca_provision.py` | Writes the CA identity into the board's secure element (GUI; `--cli provision/info/refresh-token/erase`). Needs the FACTORY firmware image (`python ../Patches/factory_flag.py on`, rebuild, flash); flash the product image again afterwards. |
| `ca_tool.py` | The CA itself: `init-root`, `init-issuing`, `issue-device`, `status`, `revoke`, `verify`, `inspect`. Also the reference strict certificate verifier. Copy of `D:\EVT2\tools\ca_tool.py`. |
| `evt2_cli.py` | USB framing used by `ca_provision.py`. Copy of `D:\EVT2\tools\evt2_cli.py`. |
| `board_status.py` | Reads the die temperature (DTS) and the share of time the main loop sleeps over SWD, without resetting the board: `python board_status.py [--watch 5]`. Works while a phone owns the USB port. |
| `ca/root/` | Root CA "EVT2 DEV Root CA" -- `cert.pem` (trust anchor written into the chip) and `key.pem` (root PRIVATE key). |
| `ca/issuing/` | Issuing (intermediate) CA "EVT2 DEV Issuing CA" -- signs device certificates and status tokens; `issued.json` = every certificate issued from here. |
| `ca/provisioned/<UID>/` | One folder per provisioned board: device certificate, status token, `record.json`. |

TEST PKI: the root and issuing private keys are unencrypted. It is the same PKI as `D:\EVT2\tools\dev_ca` (same root,
same issuing CA), so boards provisioned here and the EVT2 PC tools (`ca_peer_sim.py`, `pc_call_peer.py`, which use the
`device_2` identity from there) trust each other. For production: make a new root with `ca_tool.py init-root`, keep it
offline, and point `ca_provision.py` at the new CA folder.

Requires: `pip install pyserial cryptography`.
