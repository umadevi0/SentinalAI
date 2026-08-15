from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List

from backend.orchestrator.orchestrator import AdaptiveThreatOrchestrator
from backend.evidence_engine.evidence_engine import ThreatEvidenceEngine
from backend.trust_engine.trust_engine import TrustEngine
from backend.response_engine.response_engine import ResponseEngine
from backend.logging.logger import LoggingEngine

app = FastAPI(title='SentinelAI Backend', version='0.1.0')

orchestrator = AdaptiveThreatOrchestrator()
evidence_engine = ThreatEvidenceEngine()
trust_engine = TrustEngine()
response_engine = ResponseEngine()
logging_engine = LoggingEngine()


class EventPayload(BaseModel):
    source: str
    event_type: str
    timestamp: str
    payload: Dict[str, Any]


class EventBatch(BaseModel):
    events: List[EventPayload]


class AnalyzeRequest(BaseModel):
    url: str
    metadata: Dict[str, Any] | None = None


@app.get('/health')
def health() -> Dict[str, str]:
    return {'status': 'ok'}


@app.post('/api/events')
def ingest_events(batch: EventBatch) -> Dict[str, Any]:
    for event in batch.events:
        logging_engine.log_event(event.model_dump())
    return {'status': 'accepted', 'count': len(batch.events)}


@app.post('/api/analyze')
def analyze(request: AnalyzeRequest) -> Dict[str, Any]:
    evidence = evidence_engine.build_evidence(request.url, request.metadata)
    trust_profile = trust_engine.compute_trust_profile(evidence)
    decision = orchestrator.decide(evidence, trust_profile)
    response = response_engine.execute(decision)
    logging_engine.log_decision(decision, response)
    return {
        'decision': decision,
        'trust_profile': trust_profile,
        'response': response,
        'evidence': evidence
    }
