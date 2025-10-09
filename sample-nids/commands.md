## Install required libraries
```
sudo apt update
sudo apt install libpcap0.8 libpcap0.8-dev tcpdump

pip install -r requirements.txt
```

## start NIDS
```
sudo python sample-nids.py
```

## start traffic generator
```
sudo python generate_suspicious_traffic.py
```