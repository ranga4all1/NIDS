#!/opt/conda/envs/nids/bin/python

"""
Analyze NIDS alert logs and show summary
"""

import json
import sys
from datetime import datetime
from collections import Counter, defaultdict

def parse_log_file(filename):
    """Parse the alert log file."""
    alerts = []
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Try to parse as JSON
                try:
                    # Find JSON part (after timestamp and level)
                    if ' - WARNING - ' in line:
                        json_part = line.split(' - WARNING - ', 1)[1]
                    elif ' - CRITICAL - ' in line:
                        json_part = line.split(' - CRITICAL - ', 1)[1]
                    else:
                        continue
                    
                    alert = json.loads(json_part)
                    alerts.append(alert)
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error parsing line: {e}")
                    continue
        
        return alerts
    
    except FileNotFoundError:
        print(f"❌ Log file not found: {filename}")
        return []
    except Exception as e:
        print(f"❌ Error reading log file: {e}")
        return []

def analyze_alerts(alerts):
    """Analyze and summarize alerts."""
    if not alerts:
        print("No alerts found in log file.")
        return
    
    print("="*70)
    print(f"         NIDS ALERT ANALYSIS")
    print("="*70)
    print(f"\nTotal Alerts: {len(alerts)}")
    
    # Count by threat type
    threat_types = Counter(alert['threat_type'] for alert in alerts)
    
    print("\n" + "="*70)
    print("ALERTS BY THREAT TYPE")
    print("="*70)
    for threat_type, count in threat_types.most_common():
        print(f"  {threat_type:20s}: {count:4d} alerts")
    
    # Group by source IP
    by_source = defaultdict(list)
    for alert in alerts:
        by_source[alert['source_ip']].append(alert)
    
    print("\n" + "="*70)
    print("ALERTS BY SOURCE IP")
    print("="*70)
    for source_ip in sorted(by_source.keys()):
        alerts_from_source = by_source[source_ip]
        print(f"\n  {source_ip}: {len(alerts_from_source)} alerts")
        
        # Show threat types from this source
        types = Counter(a['threat_type'] for a in alerts_from_source)
        for threat_type, count in types.items():
            print(f"    - {threat_type}: {count}")
    
    # Show high confidence threats
    print("\n" + "="*70)
    print("HIGH CONFIDENCE THREATS (confidence > 0.8)")
    print("="*70)
    
    high_conf = [a for a in alerts if a.get('confidence', 0) > 0.8]
    
    if not high_conf:
        print("  None found")
    else:
        for i, alert in enumerate(high_conf[:10], 1):  # Show first 10
            print(f"\n  [{i}] {alert['threat_type'].upper()}")
            print(f"      Time: {alert['timestamp']}")
            print(f"      Source: {alert['source_ip']}:{alert.get('source_port', 'N/A')}")
            print(f"      Dest: {alert['destination_ip']}:{alert.get('destination_port', 'N/A')}")
            print(f"      Confidence: {alert['confidence']:.2f}")
            
            # Show specific details
            details = alert.get('details', {})
            if 'rule' in details:
                print(f"      Rule: {details['rule']}")
            if 'score' in details:
                print(f"      Anomaly Score: {details['score']:.3f}")
        
        if len(high_conf) > 10:
            print(f"\n  ... and {len(high_conf) - 10} more high confidence alerts")
    
    # Timeline - show first and last alert
    print("\n" + "="*70)
    print("TIMELINE")
    print("="*70)
    
    try:
        first = alerts[0]
        last = alerts[-1]
        
        first_time = datetime.fromisoformat(first['timestamp'])
        last_time = datetime.fromisoformat(last['timestamp'])
        duration = last_time - first_time
        
        print(f"  First alert: {first_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Last alert:  {last_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Duration:    {duration}")
        print(f"  Rate:        {len(alerts) / max(duration.total_seconds(), 1):.2f} alerts/second")
    except Exception as e:
        print(f"  Could not parse timeline: {e}")
    
    print("\n" + "="*70)

def show_recent_alerts(alerts, count=20):
    """Show the most recent alerts in detail."""
    print("\n" + "="*70)
    print(f"MOST RECENT {count} ALERTS")
    print("="*70)
    
    recent = alerts[-count:]
    
    for i, alert in enumerate(reversed(recent), 1):
        try:
            timestamp = datetime.fromisoformat(alert['timestamp'])
            time_str = timestamp.strftime('%H:%M:%S')
        except:
            time_str = "Unknown"
        
        threat = alert['threat_type']
        src = f"{alert['source_ip']}:{alert.get('source_port', '?')}"
        dst = f"{alert['destination_ip']}:{alert.get('destination_port', '?')}"
        conf = alert.get('confidence', 0)
        
        print(f"\n[{i:2d}] {time_str} | {threat:15s} | Conf: {conf:.2f}")
        print(f"     {src} -> {dst}")
        
        # Show rule or score if available
        details = alert.get('details', {})
        if 'rule' in details:
            print(f"     Rule: {details['rule']}")
        if 'score' in details:
            print(f"     Anomaly Score: {details['score']:.3f}")

def main():
    log_file = "ids_alerts.log"
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    
    print(f"\nReading alerts from: {log_file}\n")
    
    alerts = parse_log_file(log_file)
    
    if not alerts:
        print("\n❌ No alerts found or could not parse log file.")
        print("\nMake sure:")
        print("  1. The NIDS has been running")
        print("  2. Threats have been detected")
        print("  3. The log file exists: ids_alerts.log")
        sys.exit(1)
    
    analyze_alerts(alerts)
    show_recent_alerts(alerts, count=20)
    
    print("\n" + "="*70)
    print("Analysis complete!")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()