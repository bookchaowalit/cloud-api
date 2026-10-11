---
title: solo-cloud-api — Product Card
doc_id: CARD-solo-cloud-api
doc_type: product-card
verdict: invest
version: 0.1
date: 2026-10-11
status: ร่างเพื่อพิจารณา
owner: Product owner (Book Dev)
---

# solo-cloud-api — Product Card

## 1. สรุปคุณค่าในหนึ่งประโยค

ให้เจ้าของเห็นการใช้งานและ inventory ของ cloud/PaaS หลายค่ายผ่าน API เดียวโดยไม่ส่ง credential หรือ payload ของผู้ให้บริการออกไป

## 2. ปัญหาและผู้ใช้เป้าหมาย

ใช้บริการ cloud/PaaS หลายค่าย (Railway, Vercel, Render ฯลฯ) ต้องรู้ว่าใช้อะไรและค่าใช้จ่ายเท่าไรโดยไม่รั่ว secret ผู้ใช้คือเจ้าของ

## 3. สิ่งที่ทำได้จริงตอนนี้

- `server.py` เปิด API ที่ 127.0.0.1:3440 (ผูก non-loopback ได้เมื่อมี `CLOUD_API_TOKEN` เท่านั้น)
- adapter ใน `adapters/` (cloud_usage, paas_action, paas_execute, paas_inventory, render_preflight) และ registry ใน `registry/`
- โหมดเริ่มต้น offline/credential-only; `?live=true` อ่านผู้ให้บริการเมื่อสั่งชัดเจน; เทสต์ 17 ไฟล์

## 4. หลักฐานสถานะ

| รายการ | ค่า |
|---|---|
| Stack | Python (stdlib HTTP server) |
| Commit | 4 ครั้ง (2026-09-09 ถึง 2026-10-11) |
| ซอร์สโค้ด | 36 ไฟล์ / 10921 บรรทัด |
| เทสต์ | 17 ไฟล์ (ไม่ได้รันในงานนี้) |
| CI | ไม่มี workflow |
| Deploy config | ไม่มี (ทะเบียนระบุ `local`) |
| Live URL | ไม่มี |

## 5. คุณค่าและจุดต่าง

- fail-closed เมื่อ bind สาธารณะโดยไม่มี token และไม่คืน payload ผู้ให้บริการ
- **[สมมติฐาน]** ไม่มีมูลค่าขายโดยตรง

## 6. ช่องว่างสำคัญ

- adapter เป็นสำเนา vendored จาก solo-empire จึงอาจเบี่ยงจากต้นฉบับ
- ไม่มี CI และยังไม่ออนไลน์

## 7. คำตัดสิน

**`invest`** — เป็นส่วนของงาน cost/ops ที่เจ้าของใช้ มีเทสต์มากที่สุดในกลุ่มและมีนโยบายความปลอดภัยชัดเจน จะเปลี่ยนเป็น `showcase` หากเลิกใช้หลายค่ายหรือย้ายเข้า platform อื่น

## 8. ขั้นต่อไป

1. ตัดสินใจว่าจะ deploy เป็น cell ออนไลน์หรือคง local
2. ทำ sync check ระหว่าง `adapters/` กับต้นฉบับ

## การอนุมัติ

| บทบาท | สถานะ | วันที่ | ลงนาม |
|---|---|---|---|
| Product owner (Book Dev) | รอพิจารณา | — | ________ |

## แหล่งข้อมูล

- `README.md`
- `server.py`, `adapters/`, `registry/`, `tests/`
