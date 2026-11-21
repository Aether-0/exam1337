# exam1337 usage

For educational use on HTTP captures you own or have permission to inspect.

## Run the demo

```bash
python3 network_analysis.py
```

## Import

```python
import exam1337
exam1337.scan()
```

## Inspect a saved PCAP

```bash
pip install scapy
```

```python
import exam1337
print(exam1337.scan_pcap('capture.pcap'))
```

The detector reports credential field names and locations, not their values. PCAP inspection is best-effort and does not perform TCP stream reassembly. It does not decrypt HTTPS.

## Tests

```bash
python3 -m unittest discover -s tests
```
