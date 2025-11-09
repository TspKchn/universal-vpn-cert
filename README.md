Universal VPN Cert Installer (เวอร์ชั่นสุดท้าย)

สคริปต์ ติดตั้งใบรับรอง SSL/TLS แบบอัตโนมัติ สำหรับบริการ VPN แบบครบวงจร รองรับ Stunnel5, Nginx และ Webmin พร้อม Cloudflare DNS API รีโหลดอัตโนมัติ, สำรองใบรับรอง, บันทึก log และออกใบรับรอง wildcard

เวอร์ชั่นนี้ออกแบบให้ ใช้ทรัพยากรน้อย เหมาะกับเซิร์ฟเวอร์สเปคต่ำ สามารถรันเพียงครั้งเดียวเพื่อติดตั้งและ deploy ใบรับรองโดยอัตโนมัติ

ฟีเจอร์

✅ ออกใบรับรอง wildcard ECC จาก Let's Encrypt

✅ รองรับการตรวจสอบ DNS ผ่าน Cloudflare API

✅ ติดตั้งใบรับรองอัตโนมัติสำหรับ Stunnel5, Nginx และ Webmin

✅ รีโหลด service อัตโนมัติเมื่อใบรับรองถูกต่ออายุ

✅ บันทึก log พร้อมลบอัตโนมัติ (เก็บ log 7 วัน)

✅ สำรองใบรับรองเก่า (เก็บเฉพาะล่าสุด)

✅ ระบบ retry ออกใบรับรองอัตโนมัติ (3 ครั้ง)

✅ เบาเครื่อง ใช้ทรัพยากรน้อย

ความต้องการของระบบ

Ubuntu/Debian server

สิทธิ์ root

ติดตั้ง dependencies (สคริปต์ติดตั้งให้อัตโนมัติถ้ายังไม่มี):
curl, perl, libnet-ssleay-perl, libauthen-pam-perl, libio-pty-perl, openssl, wget, socat

บัญชี Cloudflare พร้อม Global API Key

การติดตั้งและใช้งาน

Clone หรือดาวน์โหลด repository:

git clone https://github.com/<your-username>/universal-vpn-cert.git
cd universal-vpn-cert


ตั้งค่าสิทธิ์ให้สคริปต์รันได้:

chmod +x universal-vpn-cert-final.sh


รันสคริปต์:

sudo ./universal-vpn-cert-final.sh


ทำตามขั้นตอน:

ใส่โดเมนหลัก (เช่น home.xq-vpn.com)

อีเมล Cloudflare

Global API Key ของ Cloudflare

สคริปต์จะ:

สำรองใบรับรองเก่า

ออกใบรับรอง wildcard ใหม่

ติดตั้งใบรับรองสำหรับ Stunnel5, Nginx และ Webmin

ตั้งค่า permission

เปิดใช้งานระบบ auto reload ผ่าน systemd path unit

ที่เก็บ log และ backup:

Log: /var/log/universal-vpn-cert/universal-vpn-cert-<timestamp>.log

Backup: /root/backup-cert/<timestamp> (เก็บเฉพาะ backup ล่าสุด)

การต่ออายุและรีโหลดอัตโนมัติ

สคริปต์สร้าง systemd path unit เพื่อตรวจสอบไฟล์ SSL:

/etc/systemd/system/universal-vpn-auto-ssl.path

/etc/systemd/system/universal-vpn-auto-ssl.service

เมื่อใบรับรองถูกต่ออายุ ไฟล์จะถูกตรวจสอบและ service จะรีโหลดอัตโนมัติ

สิทธิ์การใช้งาน

โปรเจกต์นี้เป็น open-source และสามารถใช้งานได้ฟรี

หมายเหตุ

สคริปต์นี้เป็นเวอร์ชั่น universal และปลอดภัยสำหรับเซิร์ฟเวอร์สเปคต่ำ

รันเพียงครั้งเดียว แล้วระบบ auto renewal จะทำงานเองผ่าน cron ของ acme.sh
