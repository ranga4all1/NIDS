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
conda activate nids
sudo /opt/conda/envs/nids/bin/python nids.py
```

- In another terminal start traffic generator
```
conda activate nids
sudo /opt/conda/envs/nids/bin/python generate_suspicious_traffic.py
```
