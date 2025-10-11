## Install required libraries
```
conda create -n nids python
conda deactivate
conda activate nids

sudo apt update
sudo apt install libpcap0.8 libpcap0.8-dev tcpdump

pip install -r requirements.txt
```

## start NIDS
'''
Note: Make sure to use python from your virtual environment
'''
```
sudo /opt/conda/envs/nids/bin/python nids.py
# Select interface 'lo' (loopback), if you plan to use traffic generator for testing
```
- In another terminal start traffic generator
```
conda activate nids
sudo /opt/conda/envs/nids/bin/python generate_suspicious_traffic.py

# or
sudo /opt/conda/envs/nids/bin/python simple_attack.py
```

## Demo
```
sudo /opt/conda/envs/nids/bin/python nids.py --interface lo --localhost-only

# Option 1: Only show threat detections (hide normal packets)
sudo /opt/conda/envs/nids/bin/python nids.py --interface lo --localhost-only 2>&1 | grep -E "(THREATS DETECTED|Training|Tracking|Port scan|SYN flood|🚨|⚠️|Signature|Anomaly)"
```