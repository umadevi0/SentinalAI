import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


class LoggingEngine:
    def __init__(self, path: str = 'sentinelai_logs.jsonl'):
        self.path = Path(path)

    def log_event(self, event: Dict[str, Any]) -> None:
        with self.path.open('a', encoding='utf-8') as file:
            file.write(json.dumps({
                'type': 'event',
                'timestamp': datetime.utcnow().isoformat(),
                **event
            }) + '\n')

    def log_decision(self, decision: Dict[str, Any], response: Dict[str, Any]) -> None:
        with self.path.open('a', encoding='utf-8') as file:
            file.write(json.dumps({
                'type': 'decision',
                'timestamp': datetime.utcnow().isoformat(),
                'decision': decision,
                'response': response
            }) + '\n')
