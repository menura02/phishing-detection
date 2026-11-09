# Kimlik Avı Kontrolü

Türkçe ve İngilizce e-posta, SMS ve bağlantılardaki kimlik avı belirtilerini açıklayan, tarayıcıda çalışan bir ön kontrol aracı. Uygulama sürümü `0.4.0`, analiz yöntemi `local-phishing-rules 2.1.0`, JSON şeması `2`.

## Yerelde çalıştırma

Node.js 22.18+ ve npm gerekir. İlk kurulum bağımlılıkları indirir. Uygulama çalışırken API anahtarı, ortam değişkeni veya internet bağlantısı gerekmez.

```sh
npm ci
npm run dev
```

[Yerel uygulamayı aç](http://127.0.0.1:4173). `npm run dev`, sıkı içerik güvenlik politikasıyla uyumlu üretim çıktısını oluşturur ve yerelde sunar. Kaynak değiştiğinde yeniden başlat. `npm run build` statik çıktıyı `dist/` dizinine yazar. `npm run preview` mevcut çıktıyı sunar.

## Kullanım

1. Türkçe veya İngilizce arayüzü seç. İki dildeki kurallar her analizde birlikte çalışır.
2. Mesajı yapıştır veya UTF-8 `.txt` dosyası seç. Elindeyse ilk satırlara `From:` ve `Reply-To:` (veya `Kimden:` ve `Yanıt Adresi:`) ekle. Sınırlar 20.000 Unicode kod noktası ve 100 KB (100.000 bayt).
3. **Analiz et** ile gerekçeleri, metindeki vurguları, bağlantı bulgularını ve uygulanamayan kontrolleri incele.
4. İstersen **JSON indir** veya **Yazdır / PDF olarak kaydet** düğmesini kullan. Özgün metin, alıntı ve tam URL eklemek için rapordaki seçeneği ayrıca işaretle.
5. **Temizle** ile bu sekmedeki metni ve sonucu kaldır.

## Analiz yaklaşımı ve sınırlar

Yerel ifade kuralları zaman baskısı, hassas veri veya ödeme talebi, ödül, kimlik iddiası, teslimat sorunu ve fatura uyarısı arar. Hesap doğrulama, oturum onayı, uzaktan erişim, ek dosya açma, geri arama ve QR okutma talepleri ayrı bulgular olarak gösterilir. Açık uyarı ve alıntı bağlamları bulguların ağırlığını düşürür. Tekrarlanan göstergeler yeni risk kategorileri oluşturmaz. Risk açıklaması, değerlendirmeyi belirleyen birleşimi gösterir. Örneğin bir işlem talebinin yanıltıcı bağlantıyla birlikte görülmesi yüksek risk üretebilir.

Motor, bir talebi aynı metin bölümünde hemen ardından gelen ilk bağlantıyla eşleştirir. Arada başka bir açıklama veya bağlantı varsa bulgular ayrı kalır. Boş satırları ve yaygın iletme ayraçlarını bölüm sınırı sayar. Tanınan imza bölümleri ve `>` ile başlayan alıntılar bulgularda görünür ve risk birleşimine katılmaz. Bu yaklaşım bağlantısı başka paragrafta olan veya belirgin talep içermeyen saldırıları kaçırabilir.

Bağlantı hedefleri WHATWG `URL` ayrıştırıcısıyla incelenir. Paketle gelen Public Suffix List verisi, kaydedilebilir alan adını alt alan adından ayırır. Yapısal kontroller kullanıcı bilgisi, IP, Punycode, kısaltıcı, benzer alan adı, başka bir alan adına işaret eden URL parametresi ve çalıştırılabilir dosya uzantılarını kapsar. Düz metin, `hxxps` veya `[.]` gösterimi, basit Markdown ve metin etiketli HTML bağlantıları desteklenir. Zengin biçimden düz metne yapıştırırken gizli hedef kaybolabilir.

Gönderici ve yanıt adresi kontrolü, başta bulunan düz metin başlıklarındaki birer adresin kaydedilebilir alan adını karşılaştırır. Meşru sistemler de ayrı yanıt alan adları kullanabilir. Gönderici kimlik doğrulaması, alan adı itibarı, hedef sayfa içeriği ve gerçek yönlendirmeler kontrol edilmez. Ek dosyalar açılmaz ve QR görselleri okunmaz.

Sonuç istatistiksel olasılık yerine uygulanan kuralların özetidir. “Belirgin risk işareti bulunamadı” yalnızca kuralların bir belirti yakalamadığı anlamına gelir. Yeni dil kalıpları, karmaşık bağlantı biçimleri ve bağlam yanlış pozitif veya kaçırılan bulgulara yol açabilir.

Senaryo örnekleri için [FTC kimlik avı rehberi](https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams) ve [FTC SMS rehberi](https://consumer.ftc.gov/articles/how-recognize-and-report-spam-text-messages).

## Gizlilik ve güvenlik

Mesaj, dosya ve analiz uygulama tarafından yalnızca açık sekmenin belleğinde tutulur. Analiz ağ isteği başlatmaz. Sayfa açılırken uygulamanın kendi sunucusundan genel tehdit veri dosyası yüklenir. Uygulama kullanıcı içeriğini günlüklere, kalıcı tarayıcı depolarına veya analitik sistemlerine yazmaz. Kullanıcı içeriği metin olarak gösterilir ve incelenen URL’ler tıklanabilir değildir. İçerik güvenlik politikası harici kaynak yüklemelerini ve form gönderimlerini engeller.

Varsayılan raporlar yalnızca bulgu kategorilerini ve açıklamalarını içerir. İçerik ekleme seçeneği özgün metni, alıntıları ve tam URL’leri iki rapor biçimine de dahil eder. Bu alanlar hassas veri içerebilir. İndirilen veya yazdırılan kopyalar tarayıcı ve kullanıcının seçtiği cihaz konumları tarafından yönetilir.

## Tehdit istihbaratı

```sh
npm run intel:sync
npm run dev
```

`intel:sync` iki kaynağı hemen yeniler. Otomatik yenileme için ayrı bir terminalde `npm run intel:watch` çalıştır. Süreç açıkken her saat güncelleme vadesine bakar. Zararlı adresleri 24 saatte bir, araştırma adaylarını 7 günde bir yeniler. Sayfayı tekrar açtığında en son veri dosyası alınır. Bir kaynak hata verirse onun son başarılı verisi korunur ve diğer kaynak bağımsız güncellenir. Kurulum veya geliştirme komutu tek başına harici kaynaklara bağlanmaz.

- **Zararlı adresler.** SGB API’sinden son 14 günde kaydedilen phishing alan adları ve URL’ler alınır. Ürün tam ana makine adı veya tam URL eşleştirmesi yapar. URL’de sorgu parametreleri korunur, sayfa içi parça kaldırılır. Alt alan adlarına ve ortak barındırma alanındaki diğer yollara eşleşme yayılmaz. Kaynak ve veri tarihi sonuçta ve raporda gösterilir. İki günü aşan veri eski olarak işaretlenir. Eşleşme yoksa yalnızca bu veri dosyasında kayıt bulunmadığı belirtilir. Bu bulgu, kural tabanlı riskten ayrı gösterilir. [SGB API](https://siberguvenlik.gov.tr/api/)
- **Teknik araştırmalar.** Microsoft’un phishing konu sayfasındaki makaleler başlık, tarih ve kaynak bağlantısıyla inceleme kuyruğuna alınır. Desteklenen konular otomatik etiketlenir. Yeni tespit kuralları için aday saldırı ve meşru karşı örneği değerlendirme setine ekleyip sonuçları karşılaştır. Araştırma listesi tespit kurallarını kendiliğinden değiştirmez. [Microsoft phishing araştırmaları](https://www.microsoft.com/en-us/security/blog/threat-intelligence/social-engineering-phishing/)

Yerel `.intel/` önbelleği Git’e dahil edilmez. Adresler SHA-256 özetleri olarak tutulur. Üretim derlemesi varsa güncelleyici aynı veri dosyasını `dist/` içine de yazar. Bu iş akışı yerel kullanım içindir. Veri dosyasını üçüncü taraflara dağıtmadan önce kaynakların dağıtım koşulları ayrıca doğrulanmalıdır. Adres eşleştirmesi için Web Crypto destekli HTTPS veya loopback önizleme gerekir.

## Geliştirme ve doğrulama

```sh
npm run lint
npm run typecheck
npm test
npm run build
npx playwright install chromium
npm run test:browser
```

Tarayıcı testleri statik üretim çıktısını kullanır ve önizleme sunucusunu kendisi başlatır. Kurulu Google Chrome’u kullanmak için `PLAYWRIGHT_CHANNEL=chrome` ayarlanabilir. PowerShell örneği `$env:PLAYWRIGHT_CHANNEL = 'chrome'; npm run test:browser`. Testler seçilmiş senaryolardaki kural ve arayüz davranışını doğrular. Gerçek dünya tespit doğruluğu için bir ölçüm sunmaz.

### Karşılaştırmalı değerlendirme

```sh
npm run evaluate -- development
npm run evaluate -- holdout
```

`tests/evaluation/` altında 8 geliştirme ve 12 ayrı değerlendirme senaryosu vardır. Örnekler Türkçe ve İngilizceye eşit dağılır. Bunlar kimlik bilgisi içermeyen sentetik mesajlardır ve etiketler senaryonun varsayılan bağlamını gösterir. Çıktı, her dil için yalnızca yüksek risk ve artmış veya yüksek risk eşiklerinde yakalanan saldırıları, kaçırılan saldırıları ve yanlış alarmları ayrı sayar.

| Ayrı değerlendirme seti | v0.2.0 | v0.3.0 |
| --- | ---: | ---: |
| Yüksek risk alan meşru senaryo | 4/6 | 0/6 |
| Artmış veya yüksek risk alan meşru senaryo | 4/6 | 3/6 |
| Yüksek risk alan phishing senaryosu | 4/6 | 4/6 |
| Artmış veya yüksek risk alan phishing senaryosu | 4/6 | 4/6 |

Bu ölçüm, seçilen senaryolardaki davranışı gösterir. Üretim doğruluğunu ölçmek için kimliksizleştirilmiş ve bağımsız doğrulanmış gerçek mesajlar gerekir.

- `src/analysis/` girdiyi, kuralları, sonuç tiplerini ve rapor şemasını içerir.
- `src/i18n/` arayüz ve rapor çevirilerini, `src/config.ts` geçici ürün adını ve sınırları tutar.
- `src/main.ts` ve `src/styles.css` ekran ve yazdırma akışını oluşturur.
- `tests/` birim ve tarayıcı senaryolarını kapsar.
