# Giai đoạn 3 — Threat Hunting Pipeline

## Mục tiêu

Đầu vào của giai đoạn 3 là JSON từ giai đoạn 2, ví dụ:

```json
{
  "technique_id": "T1059.001",
  "technique_name": "PowerShell",
  "evidence": "The attacker utilized PowerShell...",
  "iocs": {"ips": [], "domains": []}
}
```

Pipeline thực hiện:

```text
ATT&CK Technique
      ↓
Hunting Hypothesis
      ↓
Telemetry Selection
      ↓
Sigma baseline + KQL/SPL reference
      ↓
Load Sysmon / Windows logs
      ↓
Normalize fields
      ↓
Match suspicious events
      ↓
Benchmark TP/FP/FN/TN, Precision/Recall/F1
```

## Các technique đã có baseline

- `T1059.001` — PowerShell
- `T1053.005` — Scheduled Task
- `T1003.001` — LSASS Memory
- `T1566.001` — Spearphishing Attachment (endpoint behavior heuristic)

Có thể mở rộng thêm technique bằng cách thêm profile trong `threat_hunting/knowledge.py`.

## Chạy ngay trên Kaggle / Local

Không cần SIEM để chạy bản MVP. Chỉ cần Python và file log JSON/JSONL/CSV.

```bash
python run_phase3.py \
  --cti api_backend/mock_data/report_1.json \
  --logs hunting_lab/sample_logs/windows_sysmon_demo.jsonl \
  --output hunting_lab/output/report_1_hunting.json
```

Kết quả chứa:

- Hunting hypothesis
- Telemetry đề xuất
- Sigma rule baseline
- KQL/SPL reference query
- Danh sách suspicious events
- Precision, Recall, F1 nếu file log có ground-truth label

## Dùng EVTX thật

Cài thư viện:

```bash
pip install python-evtx
```

Sau đó truyền file `.evtx` vào `--logs`. Module `log_loader.py` sẽ parse EventData và chuẩn hóa các field phổ biến như `EventID`, `Image`, `ParentImage`, `CommandLine`, `TargetImage`, `TaskName`.

## Về Sigma / KQL / SPL

Sigma là rule portable. KQL và SPL trong output hiện là **reference query trên schema chuẩn hóa** của project, không phải query universal cho mọi SIEM. Khi tích hợp Microsoft Sentinel / Splunk thật, nên dùng Sigma converter hoặc map lại field theo schema của SIEM.

## Vì sao baseline đang deterministic thay vì để LLM tự sinh rule?

Giai đoạn 1–2 đã fine-tune model cho bài toán CTI → ATT&CK. Model đó không được huấn luyện chuyên cho detection engineering. Vì vậy Phase 3 dùng ATT&CK-driven template/rule baseline để:

1. Chạy được ngay trên Kaggle;
2. Có kết quả lặp lại để benchmark;
3. Tránh LLM sinh rule sai cú pháp hoặc hallucinate field;
4. Sau này có thể thêm một instruction LLM để sinh hypothesis/rule, rồi validate và fallback về baseline này.

## Cấu trúc file

```text
threat_hunting/
├── knowledge.py      # ATT&CK → hypothesis/telemetry/detection baseline
├── plan.py           # tạo hunting plan + Sigma/KQL/SPL
├── log_loader.py     # JSON/JSONL/CSV/EVTX → normalized events
├── hunter.py         # matching engine
├── evaluation.py     # TP/FP/TN/FN + Precision/Recall/F1
└── pipeline.py       # nối toàn bộ Phase 3

hunting_lab/
├── sample_logs/
│   └── windows_sysmon_demo.jsonl
└── output/
```
