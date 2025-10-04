# Scapy L2/L3 Toolkit (v9.3)

Scapy を使った学習・検証向けの L2/L3 ツール GUI。ICMP/TCP/UDP の基本操作、DNS(UDP/TCP/DoT) 送出、ARP スキャン、トレーサ、PCAP 送出、FastAPI+Uvicorn の簡易 HTTP サーバ、UDP エコー、リアルタイムスニファ、環境/ネットワーク情報ポップアップを 1 画面に集約。

- **GUI**: FreeSimpleGUI（推奨） / PySimpleGUI v4（フォールバック）
- **HTTP ヘルパ**: FastAPI + Uvicorn
- **OS**: Windows / macOS / Linux（raw socket は通常 **管理者権限** が必要）

> ⚠️ 許可された環境・範囲でのみ使用してください。スキャンやアクティブテストは法令・社内ポリシーの対象です。

---

## 目次

1. [主な機能](#主な機能)  
2. [要件](#要件)  
3. [インストール](#インストール)  
4. [実行方法](#実行方法)  
5. [基本的な使い方](#基本的な使い方)  
6. [HTTP ヘルパ API](#http-ヘルパ-api)  
7. [ポップアップ（Env/Versions & Network）](#ポップアップenvversions--network)  
8. [トラブルシューティング](#トラブルシューティング)  
9. [スクリーンショット](#スクリーンショット)  
10. [ライセンス](#ライセンス)  
11. [謝辞](#謝辞)

---

## 主な機能

- 🇯🇵/🇬🇧 UI トグル（日本語/英語）
- Endpoints（送信元/宛先/TTL/Timeout/Retry）
- **Ping 1/2-way**, **SYN 1/3-way**, **TCP Scan**
- **DNS 送出**（UDP/TCP/DoT）  
  - EDNS0 / DO / NSID / EDE（サブセット）
- **ARP Scan**
- **Traceroute**（ICMP/UDP/TCP、TTL 並列、PTR ルックアップ）
- **PCAP 送出**（IP 書換、send/sendp、sendpfast=tcpreplay）
- **Custom Payload 送信**（ICMP/TCP/UDP/RAW）
- **ローカル HTTP サーバ**（FastAPI + Uvicorn）  
  - `/healthz`, `/echo`, `/time`, `/static/*`（docroot 指定時）
- **UDP Echo サーバ**
- **リアルタイムスニファ**（PPS スパークライン、プロトコル比率、ロール PCAP、CSV）
- **Env/Versions ポップアップ**（※GUI ライブラリの**バージョンは一切プローブしない**安全設計）
- **Network Info ポップアップ**（ホスト/IF/ルート/DNS）

---

## 要件

- Python **3.8+**
- 推奨: `FreeSimpleGUI`（なければ `PySimpleGUI<5`）
- 必須: `scapy`
- HTTP ヘルパ利用時: `fastapi`, `uvicorn`
- 任意: `tcpreplay`（`sendpfast` 利用時）
- Raw socket 操作のため **管理者/Administrator** もしくは **sudo** が必要

---

## インストール

```bash
python -m venv .venv
# Windows
. .venv/Scripts/activate
# macOS/Linux
source .venv/bin/activate

pip install --upgrade pip
pip install FreeSimpleGUI scapy fastapi uvicorn
# FreeSimpleGUI が使えない場合のフォールバック
pip install "PySimpleGUI<5"
PySimpleGUI v5 は非対応（v4 API 前提）。

実行方法
bash
コードをコピーする
python scapy_gui.py
上部バー：言語切替、ポートヘルス（✅/❌）、Env/Versions、Network Info ボタン

起動時に権限警告が出る場合あり（Raw socket のため）

基本的な使い方
Local Servers

Start HTTP：FastAPI+Uvicorn を起動（/healthz で疎通確認）

Start UDP Echo：UDP エコーサーバ起動

右上「Ports:」に HTTP/UDP の状態が反映

Receiver / Realtime

BPF フィルタ指定、ローテ PCAP、CSV エクスポート

DNS

UDP/TCP/DoT の切替、EDNS/DO/NSID/EDE（サブセット）を指定

Missions

学習用の簡易チェックボックス（Ping 成功など）

HTTP ヘルパ API
GET /healthz → {"status":"ok"}

GET /echo?q=hello → "hello"

GET /time → {"now": "YYYY-MM-DDTHH:MM:SSZ"}

GET /static/* → Doc root 指定時のみ

ポップアップ（Env/Versions & Network）
Env/Versions

Python/OS/OpenSSL、主要モジュール（Scapy/FastAPI/Uvicorn/…）

sys.path、tcpreplay 有無、conf.iface、HTTP/UDP ヘルパ状態

注意：GUI ライブラリ（FreeSimpleGUI/PySimpleGUI）のバージョンは取得しません（ベンダリンク/ポップアップによるクラッシュ回避）

Network Info

Hostname/FQDN、推定ローカル IP

Scapy IF 一覧、Bind 候補、ルーティングテーブル、既定経路

/etc/resolv.conf の nameserver（Unix系）

トラブルシューティング
GUI が起動しない

FreeSimpleGUI または PySimpleGUI<5 を確認

Permission warning が出る

管理者/Administrator または sudo で再実行

HTTP ヘルパが ❌

fastapi/uvicorn 導入、ポート競合、FW を確認

DoT が失敗

853/TCP の外向き許可、TLS インスペクションの有無を確認

スクリーンショット
README.screenshots.md を参照し、./screenshots/*.png を配置してください。

ライセンス
（例：MIT License）

謝辞
GUI: FreeSimpleGUI / PySimpleGUI

Networking: Scapy

HTTP: FastAPI / Uvicorn

Replay: tcpreplay