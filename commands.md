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
```
# sudo python nids.py
sudo /opt/conda/envs/nids/bin/python nids.py
```

## start traffic generator
```
# sudo python generate_suspicious_traffic.py
sudo /opt/conda/envs/nids/bin/python generate_suspicious_traffic.py
```