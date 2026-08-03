"""
API usage statistics module
Tracks and records large language model API calls, token consumption, costs, etc.
"""

import os
import json
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

class APIUsageRecord:
    """API usage record"""
    def __init__(self, **kwargs):
        self.timestamp = kwargs.get("timestamp", datetime.now().isoformat())
        self.model = kwargs.get("model", "unknown")
        self.provider = kwargs.get("provider", "unknown")
        self.prompt_tokens = kwargs.get("prompt_tokens", 0)
        self.completion_tokens = kwargs.get("completion_tokens", 0)
        self.total_tokens = kwargs.get("total_tokens", 0)
        self.cost_usd = kwargs.get("cost_usd", 0.0)
        self.request_id = kwargs.get("request_id", str(uuid.uuid4()))
        self.success = kwargs.get("success", True)
        self.error_message = kwargs.get("error_message", None)
        self.duration_ms = kwargs.get("duration_ms", 0)

class APIUsageSummary:
    """Usage summary"""
    def __init__(self):
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0
        self.total_cost_usd = 0.0
        self.average_cost_per_request = 0.0
        self.average_tokens_per_request = 0.0
        self.success_rate = 0.0
        self.start_time = None
        self.end_time = None
        self.duration_hours = 0.0
        self.model_usage = {}

class APIUsageTracker:
    """API usage tracker"""
    def __init__(self, storage_dir: str = "usage_stats"):
        self.storage_dir = storage_dir
        self.session_records: List[APIUsageRecord] = []
        self.session_start_time = datetime.now()
        self.session_end_time = None
        self.pricing = {
            # Price table (USD per 1000 tokens)
            "gpt": {
                "gpt-4": {"input": 0.030, "output": 0.060},         # $30/$60 per 1M = $0.030/$0.060 per 1K
                "gpt-4-turbo": {"input": 0.010, "output": 0.030},   # $10/$30 per 1M = $0.010/$0.030 per 1K
                "gpt-4o": {"input": 0.0025, "output": 0.010},       # $2.50/$10.00 per 1M = $0.0025/$0.010 per 1K
                "gpt-4.1": {"input": 0.002, "output": 0.008},       # $2.00/$8.00 per 1M = $0.002/$0.008 per 1K
                "gpt-4.1-mini": {"input": 0.0004, "output": 0.0016}, # $0.40/$1.60 per 1M = $0.0004/$0.0016 per 1K
                "gpt-3.5-turbo": {"input": 0.0015, "output": 0.002}, # $1.5/$2.0 per 1M = $0.0015/$0.002 per 1K
                "gpt-3.5-turbo-16k": {"input": 0.003, "output": 0.004}, # $3.0/$4.0 per 1M = $0.003/$0.004 per 1K
            },
            "deepseek": {
                "deepseek-chat": {"input": 0.00027, "output": 0.0011},     # $0.27/$1.10 per 1M = $0.00027/$0.0011 per 1K
                "deepseek-coder": {"input": 0.00027, "output": 0.0011},    # Same as deepseek-chat
                "deepseek-reasoner": {"input": 0.00055, "output": 0.00219}, # $0.55/$2.19 per 1M = $0.00055/$0.00219 per 1K
                "deepseek-r1": {"input": 0.00055, "output": 0.00219},      # DeepSeek R1 alias
            },
            "qwen": {
                "qwen-turbo": {"input": 0.0005, "output": 0.001},   # Estimate: $0.5/$1.0 per 1M = $0.0005/$0.001 per 1K
                "qwen-plus": {"input": 0.001, "output": 0.002},     # Estimate: $1.0/$2.0 per 1M = $0.001/$0.002 per 1K
                "qwen-max": {"input": 0.002, "output": 0.004},      # Estimate: $2.0/$4.0 per 1M = $0.002/$0.004 per 1K
            },
        }

    def record_api_call(self, **kwargs):
        """Record an API call"""
        # Generate request ID
        if "request_id" not in kwargs:
            kwargs["request_id"] = str(uuid.uuid4())
        # Calculate cost
        if "cost_usd" not in kwargs:
            kwargs["cost_usd"] = self.calculate_cost(
                kwargs.get("provider", "unknown"),
                kwargs.get("model", "unknown"),
                kwargs.get("prompt_tokens", 0),
                kwargs.get("completion_tokens", 0)
            )
        # Create record
        record = APIUsageRecord(**kwargs)
        # Add to session records
        self.session_records.append(record)
        # Save to file
        self.save_record(record)

    def save_record(self, record: APIUsageRecord):
        """Save a record to file"""
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)
        date_str = record.timestamp.split("T")[0]
        file_path = os.path.join(self.storage_dir, f"usage_{date_str}.jsonl")
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record.__dict__, ensure_ascii=False) + "\n")

    def calculate_cost(self, provider: str, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculate API call cost based on per-1K-token pricing"""
        # Handle None values
        if not provider or not model:
            return 0.0
        # Use default price
        provider = provider.lower()
        model = model.lower()
        price = self.pricing.get(provider, {}).get(model, None)
        if not price:
            return 0.0
        # Calculate cost: (tokens / 1,000) * price_per_1K_tokens
        cost = (prompt_tokens / 1000) * price["input"] + (completion_tokens / 1000) * price["output"]
        return round(cost, 6)

    def get_session_summary(self) -> APIUsageSummary:
        """Get usage summary for the current session"""
        if not self.session_records:
            return self._create_empty_summary()
        
        total_requests = len(self.session_records)
        successful_requests = len([r for r in self.session_records if r.success])
        failed_requests = total_requests - successful_requests
        
        total_prompt_tokens = sum(r.prompt_tokens for r in self.session_records)
        total_completion_tokens = sum(r.completion_tokens for r in self.session_records)
        total_tokens = sum(r.total_tokens for r in self.session_records)
        total_cost = sum(r.cost_usd for r in self.session_records)
        
        average_cost = total_cost / total_requests if total_requests > 0 else 0
        average_tokens = total_tokens / total_requests if total_requests > 0 else 0
        success_rate = (successful_requests / total_requests) * 100 if total_requests > 0 else 0
        
        end_time = datetime.now()
        duration = end_time - self.session_start_time
        duration_hours = duration.total_seconds() / 3600
        
        summary = APIUsageSummary()
        summary.total_requests = total_requests
        summary.successful_requests = successful_requests
        summary.failed_requests = failed_requests
        summary.total_prompt_tokens = total_prompt_tokens
        summary.total_completion_tokens = total_completion_tokens
        summary.total_tokens = total_tokens
        summary.total_cost_usd = total_cost
        summary.average_cost_per_request = average_cost
        summary.average_tokens_per_request = average_tokens
        summary.success_rate = success_rate
        summary.start_time = self.session_start_time.isoformat()
        summary.end_time = end_time.isoformat()
        summary.duration_hours = duration_hours
        for record in self.session_records:
            summary.model_usage[record.model] = summary.model_usage.get(record.model, 0) + 1
        
        return summary
    
    def _create_empty_summary(self) -> APIUsageSummary:
        """Create an empty summary"""
        now = datetime.now()
        return APIUsageSummary()

    def get_session_records(self) -> List[Dict[str, Any]]:
        """Get all session records as dicts"""
        return [r.__dict__ for r in self.session_records]

    def reset_session(self):
        """Reset current session statistics"""
        self.session_records = []
        self.session_start_time = datetime.now()
        self.session_end_time = None
    
    def get_historical_summary(self, days: int = 7) -> Dict[str, Any]:
        """Get historical usage summary"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        all_records = []

        # Read all records within the given date range
        current_date = start_date
        while current_date <= end_date:
            date_str = current_date.strftime("%Y-%m-%d")
            filename = os.path.join(self.storage_dir, f"usage_{date_str}.jsonl")
            
            if os.path.exists(filename):
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        for line in f:
                            if line.strip():
                                record_data = json.loads(line)
                                record = APIUsageRecord(**record_data)
                                all_records.append(record)
                except Exception as e:
                    print(f"Error reading history file {filename}: {e}")

            current_date += timedelta(days=1)

        # Group statistics by date
        daily_stats = {}
        for record in all_records:
            date = record.timestamp[:10]  # extract date part
            if date not in daily_stats:
                daily_stats[date] = {
                    "total_requests": 0,
                    "total_tokens": 0,
                    "total_cost": 0.0,
                    "models": set()
                }
            
            daily_stats[date]["total_requests"] += 1
            daily_stats[date]["total_tokens"] += record.total_tokens
            daily_stats[date]["total_cost"] += record.cost_usd
            daily_stats[date]["models"].add(record.model)
        
        # Convert set to list for JSON serialization
        for date in daily_stats:
            daily_stats[date]["models"] = list(daily_stats[date]["models"])

        return {
            "period": f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
            "total_records": len(all_records),
            "daily_stats": daily_stats,
            "total_cost": sum(record.cost_usd for record in all_records),
            "total_tokens": sum(record.total_tokens for record in all_records)
        }
    
    def print_session_summary(self):
        """Print usage summary for the current session"""
        summary = self.get_session_summary()

        print("\n=== API Usage Statistics ===")
        print(f"Session start time: {summary.start_time}")
        print(f"Session end time: {summary.end_time}")
        print(f"Session duration: {summary.duration_hours:.2f} hours")
        print()

        print("Request statistics:")
        print(f"  Total requests: {summary.total_requests}")
        print(f"  Successful requests: {summary.successful_requests}")
        print(f"  Failed requests: {summary.failed_requests}")
        print(f"  Success rate: {summary.success_rate:.1f}%")
        print()

        print("Token statistics:")
        print(f"  Total prompt tokens: {summary.total_prompt_tokens:,}")
        print(f"  Total completion tokens: {summary.total_completion_tokens:,}")
        print(f"  Total tokens: {summary.total_tokens:,}")
        print(f"  Average tokens per request: {summary.average_tokens_per_request:.0f}")
        print()

        print("Cost statistics:")
        print(f"  Session cost: ${summary.total_cost_usd:.6f}")
        print(f"  Average cost per request: ${summary.average_cost_per_request:.6f}")

        # Show more detail on accumulated cost
        if summary.total_cost_usd > 0:
            print(f"  Session cost (milli-USD): {summary.total_cost_usd * 1000:.3f} m$")
            print(f"  Session cost (micro-USD): {summary.total_cost_usd * 1000000:.1f} μ$")

        # Show historical accumulated cost
        try:
            historical = self.get_historical_summary()
            total_historical_cost = historical.get("total_cost", 0.0)
            if total_historical_cost > 0:
                print(f"  Historical total cost: ${total_historical_cost:.6f}")
                print(f"  Historical total cost (milli-USD): {total_historical_cost * 1000:.3f} m$")
        except Exception:
            pass  # Ignore failures when fetching historical data
        print()

        if summary.total_requests > 0:
            print("Recent records:")
            for i, record in enumerate(self.session_records[-5:], 1):  # show last 5 records
                status = "✓" if record.success else "✗"
                cost_display = f"${record.cost_usd:.6f}"
                if record.cost_usd < 0.0001:
                    cost_display += f" ({record.cost_usd * 1000000:.1f}μ$)"
                print(f"  {i}. [{status}] {record.model} - {record.total_tokens} tokens - {cost_display}")
    
    def export_summary(self, output_file: str = None):
        """Export usage summary to a file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.storage_dir, f"usage_summary_{timestamp}.json")
        
        summary = self.get_session_summary()
        historical = self.get_historical_summary()
        
        export_data = {
            "session_summary": summary.__dict__,
            "historical_summary": historical,
            "detailed_records": [r.__dict__ for r in self.session_records]
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            print(f"Usage summary exported to: {output_file}")
        except Exception as e:
            print(f"Error exporting usage summary: {e}")

    def reset_session(self):
        """Reset current session statistics"""
        self.session_records.clear()
        self.session_start_time = datetime.now()
        print("Session statistics reset") 