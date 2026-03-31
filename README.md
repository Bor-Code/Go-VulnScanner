# 🕸️ Go-VulnScanner | Eşzamanlı Web Zafiyet Tarayıcısı

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![Concurrency](https://img.shields.io/badge/Architecture-Worker%20Pool-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Focus-DAST%20Security-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Go-VulnScanner**, siber güvenlik profesyonelleri ve sızma testi uzmanları (pentesters) için Go (Golang) dilinin eşzamanlılık (concurrency) gücü kullanılarak sıfırdan geliştirilmiş, yüksek performanslı bir Dinamik Uygulama Güvenliği Testi (DAST) aracıdır.

Basit script tabanlı tarayıcıların aksine; belleği yormadan binlerce isteği yönetebilir, hedef DOM ağacını akıllıca ayrıştırır ve yapılandırılmış JSON raporları sunar.

---

## İçindekiler
1. [Neden Bu Proje?](#-neden-bu-proje)
2. [Temel Özellikler](#-temel-özellikler)
3. [Mimari Tasarım](#-mimari-tasarım)
4. [Kurulum](#-kurulum)
5. [Kullanım ve Parametreler](#-kullanım-ve-parametreler)
6. [Örnek Rapor Çıktısı](#-örnek-rapor-çıktısı)
7. [Yol Haritası (Roadmap)](#-yol-haritası)
8. [Yasal Uyarı](#-yasal-uyarı)

---

## Neden Bu Proje?
Geleneksel Python veya Ruby tabanlı tarayıcılar (thread limitleri ve GIL nedeniyle) büyük ölçekli taramalarda darboğaz yaşayabilirler. Bu proje, Go'nun **Goroutine** ve **Channel** mimarisini kullanarak;
* CPU ve RAM tüketimini minimumda tutmayı,
* Tarama sürelerini drastik ölçüde kısaltmayı,
* WAF/IPS sistemlerini tetiklememek için hassas hız kontrolü sağlamayı hedeflemiştir.

---

## Temel Özellikler

- **Gelişmiş Eşzamanlılık:** Worker Pool (İşçi Havuzu) deseni sayesinde, belirlediğiniz thread sayısını asla aşmadan (Goroutine sızıntısı olmadan) güvenle çalışır.
- **Akıllı DOM Ayrıştırıcı:** Hedef URL'yi sadece bir string olarak görmez. `golang.org/x/net/html` paketi ile sayfanın anatomisini çıkarır.
  - Sayfa içi derin (in-scope) linkleri gezer.
  - GET parametrelerini bulur.
  - Gizli (Hidden) input'ları ve POST formu hedeflerini yakalar.
- **Trafik Kontrolü (Rate Limiting):** Token-Bucket algoritması ile hedef sunucuya saniyede kaç istek (Req/Sec) atılacağını milisaniye hassasiyetinde yönetir.
- **Oturum (Session) Desteği:** Kimlik doğrulaması gerektiren (Authentication) admin panelleri veya kapalı sistemler için Cookie ve Custom Header enjeksiyonu destekler.
- **Temiz Raporlama:** Bulgular anlık olarak terminale düşerken, arka planda Data-Race engelleme (Mutex) ile güvenli bir JSON dosyasına işlenir.

---

## 🏗️ Mimari Tasarım

Proje 3 ana modülden oluşmaktadır:
1. **Crawler (Örümcek):** Sitedeki tüm saldırı yüzeylerini (GET url'leri, POST formları) çıkarır ve tekrar döngüye girmemek için ziyaret edilenleri `sync.RWMutex` ile izole edilmiş bir hafızada (map) tutar.
2. **Fuzzer (Saldırı Motoru):** Bulunan her parametreye hedeflenmiş SQLi ve XSS payload'larını enjekte edip sunucuya fırlatır.
3. **Analyzer & Reporter:** Dönen HTTP yanıtlarını (Response Body) analiz eder; veritabanı syntax hatalarını veya yansıyan XSS metinlerini yakalayıp Thread-Safe bir şekilde JSON olarak dışa aktarır.

---

## Kurulum

Aracı derlemek ve kullanmak için sisteminizde Go kurulu olmalıdır.

```bash
# 1. Depoyu bilgisayarınıza klonlayın
git clone [https://github.com/SENIN-ADIN/Go-VulnScanner.git](https://github.com/SENIN-ADIN/Go-VulnScanner.git)

# 2. Proje dizinine girin
cd Go-VulnScanner

# 3. Kütüphane bağımlılıklarını güncelleyin
go mod tidy

# 4. Projeyi işletim sisteminize göre derleyin
go build -o vulnscanner cmd/scanner/main.go