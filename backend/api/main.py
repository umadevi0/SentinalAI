import time
from typing import Any, Dict, List

from fastapi import FastAPI
from pydantic import BaseModel

from backend.orchestrator.orchestrator import AdaptiveThreatOrchestrator
from backend.evidence_engine.evidence_engine import ThreatEvidenceEngine
from backend.trust_engine.trust_engine import TrustEngine
from backend.response_engine.response_engine import ResponseEngine
from backend.logging.logger import LoggingEngine
from backend.ml.predict import load_model_as_predictor

app = FastAPI(title='SentinelAI Backend', version='2.0.0')

orchestrator = AdaptiveThreatOrchestrator()
evidence_engine = ThreatEvidenceEngine()
trust_engine = TrustEngine()
response_engine = ResponseEngine()
logging_engine = LoggingEngine()


def _make_predictor():
    try:
        return load_model_as_predictor('auto')
    except Exception:
        return None


predictor = _make_predictor()


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
    timing: Dict[str, float] = {}
    t0 = time.perf_counter()

    t_a = time.perf_counter()
    evidence = evidence_engine.build_evidence(request.url, request.metadata)
    timing['evidence_build'] = round((time.perf_counter() - t_a) * 1000, 3)

    t_b = time.perf_counter()
    trust_profile = trust_engine.compute_trust_profile(evidence)
    timing['trust_fusion'] = round((time.perf_counter() - t_b) * 1000, 3)

    t_c = time.perf_counter()
    decision = orchestrator.decide(evidence, trust_profile,
                                   metadata=request.metadata,
                                   predictor=predictor)
    timing['decision'] = round((time.perf_counter() - t_c) * 1000, 3)

    t_d = time.perf_counter()
    response = response_engine.execute(decision)
    timing['response'] = round((time.perf_counter() - t_d) * 1000, 3)

    timing['total_ms'] = round((time.perf_counter() - t0) * 1000, 3)

    logging_engine.log_decision(decision, response)
    return {
        'decision': decision,
        'trust_profile': trust_profile,
        'response': response,
        'evidence': evidence,
        'timing_ms': timing,
    }