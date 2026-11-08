# NexoraAI V14.2 — Intellectual Property (IP) & Open-Source Compliance Audit Report

> **NOTICE:** This technical IP audit inspects every model checkpoint, dataset, tokenizer asset, Python runtime dependency, and UI library in the NexoraAI V14.2 repository. **Legal sign-off by qualified intellectual property counsel is required before commercial licensing or public distribution.**

## 1. Strict Separation of Neural Model Assets (Section 10 Compliance)

| Asset Name & Path | Exact Parameters & Tensors | Provenance & Architecture | Applicable License / IP Status | Commercial Distribution Decision |
| :--- | :--- | :--- | :--- | :--- |
| **Model A: Native NexoraAI V14.2 (`engine_v14_1/checkpoints/v14_neural/model.safetensors`)** | `15,684,488` parameters (`39` FP32 tensors, `62,741,608` bytes, SHA-256 `d285ab0e...`) | `NexoraCausalMoETransformer_V14` (`d_model=384, 6 heads, 8 SwiGLU experts, vocab=4096`), initialized from scratch with NumPy PRNG (`seed=1400`) and trained locally. | First-party custom architecture (`Pratik Parth`); **however, verify underlying training corpus rights (`data/training/train.jsonl`) before commercial sale.** | **ELIGIBLE FOR COMMERCIAL DISTRIBUTION** (Subject to training dataset IP sign-off). |
| **Model B: Qwen-Compatible LoRA Adapter (`engine_v14_1/checkpoints/best/adapter_model.safetensors`)** | `8,798,208` adapter parameters (`336` FP32 tensors, `35,237,176` bytes, SHA-256 `6f17e027...`) | 24-layer PEFT LoRA adapter (`d_model=896, kv_dim=128, d_ff=4864, r=16`) targeting `Qwen/Qwen2.5-0.5B-Instruct`. | Requires `Qwen/Qwen2.5-0.5B-Instruct` base model (**Apache License 2.0**, Alibaba Cloud / Qwen Team). Any distribution with or for Qwen requires Apache-2.0 attribution notices and preservation of `NOTICE`/`LICENSE` files. | **QUARANTINED FROM COMMERCIAL DISTRIBUTION (`commercial_distribution_allowed = 0`)** until counsel reviews base-model and dataset obligations. |
| **Native Vocabulary (`engine_v14_1/tokenizer/vocab.json`)** | `4,096` tokens (`256` byte fallbacks + domain word/subword vocabulary) | Built deterministically from local corpus token frequencies (`tokenizer/nexora_tokenizer.py`). | First-party generated asset (`0` third-party BPE merges copied from proprietary tokenizers). | **CLEARED** |
| **Semantic Memory Store (`engine_v14_1/memory/documents.jsonl` & `semantic_index.npz`)** | `3,734` documents (`1,433,856` float32 values) | Derived from `data/training/train.jsonl` (`3,704` rows) + `data/self_evolved/self_evolved_verified.jsonl` (`15` rows). | **REQUIRES DATASET PROVENANCE VERIFICATION:** `train.jsonl` contains general instruction-tuning conversations that must be audited to confirm commercial redistribution rights. | **AUDIT REQUIRED BEFORE BUNDLING `documents.jsonl` COMMERCIALLY** |

## 2. Third-Party Software Dependency License Inventory

NexoraAI V14.2 does **not** claim ownership of any third-party open-source library. All runtime dependencies use permissive open-source licenses compatible with commercial distribution when accompanied by their copyright notices (see `Third-Party Notices` in `commercial_platform/legal/LEGAL_DRAFTS_BUNDLE.md`):

| Package / Dependency | Pinned Version (`requirements.lock`) | SPDX License | Commercial Distribution Obligations | Ownership Claimed by NexoraAI? |
| :--- | :--- | :--- | :--- | :--- |
| **Python Standard Library** (`sqlite3`, `hashlib`, `hmac`, `http.server`, `zlib`) | Python `3.11+` | `PSF-2.0` | Include PSF License notice if bundling a standalone Python interpreter. | **No** (PSF) |
| **NumPy** (`numpy`) | `2.1.3` | `BSD-3-Clause` | Retain BSD-3-Clause copyright notice and disclaimer in documentation. | **No** (NumPy Developers) |
| **SciPy** (`scipy`) | `1.15.2` | `BSD-3-Clause` | Retain BSD-3-Clause copyright notice and disclaimer. | **No** (SciPy Developers) |
| **SymPy** (`sympy`) | `1.13.3` | `BSD-3-Clause` | Retain BSD-3-Clause copyright notice and disclaimer. | **No** (SymPy Development Team) |
| **PyYAML** (`PyYAML`) | `6.0` | `MIT` | Retain MIT copyright and permission notice. | **No** (Kirill Simonov) |
| **FastAPI / Pydantic / Uvicorn** (Optional API host) | `0.92.0` / `1.10.4` / `0.17.6` | `MIT` / `BSD-3-Clause` | Retain MIT and BSD-3-Clause notices. | **No** (Sebastián Ramírez / Samuel Colvin / Encode) |
| **PySide6 (Qt for Python)** (Optional Desktop GUI) | Optional Host Dependency | `LGPL-3.0-only` | **CRITICAL LGPL-3.0 OBLIGATION:** If distributing a desktop binary bundling `PySide6`, you MUST dynamically link Qt/PySide6 libraries (never statically link without a commercial Qt license), provide the LGPL-3.0 text, and allow end users to replace the shared Qt libraries—OR use the built-in `Tkinter` (`PSF-2.0`) / native webview interface. | **No** (The Qt Company) |
| **Inter & JetBrains Mono Fonts / Lucide Icons** (Web UI) | Web CDN | `OFL-1.1` / `ISC` | Open Font License 1.1 and ISC License permit commercial web/app embedding with copyright attribution. | **No** (Rasmus Andersson / JetBrains / Lucide Contributors) |

## 3. Mandatory Pre-Launch IP Checklist
1. **Quarantine Enforcement (`PASS`):** `DistributionService` blocks commercial downloads of `rel_v14_1_qwen_lora_quarantined` (`commercial_distribution_allowed = 0`, verified by `sec_14_qwen_adapter_quarantined_and_single_use_download_token = PASS`).
2. **Training Corpus Provenance Review (`ACTION REQUIRED BY OWNER`):** Before selling commercial licenses that bundle `memory/documents.jsonl` or weights trained on `data/training/train.jsonl`, verify that every upstream source in `train.jsonl` permits commercial derivative use, or replace any third-party instruction rows with 100% first-party authored domain records.
3. **PySide6 Dynamic Linking (`ACTION REQUIRED IF PACKAGING DESKTOP INSTALLER`):** Keep `PySide6` dynamically linked (or use a commercial Qt license) to satisfy LGPLv3 requirements.
