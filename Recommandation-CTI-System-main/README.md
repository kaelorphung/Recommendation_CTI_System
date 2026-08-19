# Recommandation-CTI-System
Hệ thống tự động hóa phân tích mối đe dọa bằng AI.
## Phase 3 - Threat Hunting

Phase 3 đã được thêm vào repo. Chạy local hoặc Kaggle bằng:

```bash
python run_phase3.py \
  --cti api_backend/mock_data/report_1.json \
  --logs hunting_lab/sample_logs/windows_sysmon_demo.jsonl \
  --output hunting_lab/output/report_1_hunting.json
```

Xem chi tiết tại `PHASE3_THREAT_HUNTING.md` hoặc notebook `notebooks/phase3_kaggle_demo.ipynb`.
