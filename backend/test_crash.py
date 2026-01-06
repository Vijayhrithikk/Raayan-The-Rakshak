from datetime import datetime
try:
    now_naive = datetime.now()
    query_time_str = "2026-01-05T10:00:00Z"
    query_time_aware = datetime.fromisoformat(query_time_str.replace('Z', '+00:00'))
    
    print(f"Naive: {now_naive}")
    print(f"Aware: {query_time_aware}")
    
    if now_naive < query_time_aware:
        print("Comparison worked!")
except Exception as e:
    print(f"CRASH: {e}")
