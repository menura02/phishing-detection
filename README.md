# Kimlik Avı Kontrolü

Türkçe ve İngilizce e-posta, SMS ve bağlantılardaki kimlik avı belirtilerini açıklayan, tarayıcıda çalışan bir ön kontrol aracı. Uygulama sürümü `0.6.0`, analiz yöntemi `local-phishing-rules 2.2.0`, JSON şeması `2`.

## Yerelde çalıştırma

Node.js 22.18+ ve npm gerekir. İlk kurulum bağımlılıkları indirir. Uygulama çalışırken API anahtarı, ortam değişkeni veya internet bağlantısı gerekmez.

```sh
npm ci
npm run dev
```

[Yerel uygulamayı aç](http://127.0.0.1:4173). `npm run dev`, sıkı içerik güvenlik politikasıyla uyumlu üretim çıktısını oluşturur ve yerelde sunar. Kaynak değiştiğinde yeniden başlat. `npm run build` statik çıktıyı `dist/` dizinine yazar. `npm run preview` mevcut çıktıyı sunar.

## Kullanım

1. Türkçe veya İngilizce arayüzü seç. İki dildeki kurallar her analizde birlikte çalışır.
2. Mesajı yapıştır veya bir dosya seç. UTF-8 `.txt` için sınır 100 KB, özgün `.eml` için 2 MB. Çıkarılan analiz metni en fazla 20.000 Unicode kod noktası olabilir. Düz metin kullanıyorsan elindeki `From:` ve `Reply-To:` (veya `Kimden:` ve `Yanıt Adresi:`) satırlarını en üste ekleyebilirsin.
3. **Analiz et** ile gerekçeleri, metindeki vurguları, bağlantı bulgularını ve uygulanamayan kontrolleri incele.
4. İstersen **JSON indir** veya **Yazdır / PDF olarak kaydet** düğmesini kullan. Özgün metin, alıntı ve tam URL eklemek için rapordaki seçeneği ayrıca işaretle.
5. **Temizle** ile bu sekmedeki metni ve sonucu kaldır.

## Analiz yaklaşımı ve sınırlar

Yerel ifade kuralları zaman baskısı, hassas veri veya ödeme talebi, ödül, kimlik iddiası, teslimat sorunu ve fatura uyarısı arar. Hesap doğrulama, oturum onayı, uzaktan erişim, ek dosya açma, geri arama ve QR okutma talepleri ayrı bulgular olarak gösterilir. Açık uyarı ve alıntı bağlamları bulguların ağırlığını düşürür. Tekrarlanan göstergeler yeni risk kategorileri oluşturmaz. Risk açıklaması, değerlendirmeyi belirleyen birleşimi gösterir. Örneğin bir işlem talebinin yanıltıcı bağlantıyla birlikte görülmesi yüksek risk üretebilir.

Motor, bir talebi aynı metin bölümünde hemen ardından gelen ilk bağlantıyla eşleştirir. Arada başka bir açıklama veya bağlantı varsa bulgular ayrı kalır. Boş satırları ve yaygın iletme ayraçlarını bölüm sınırı sayar. Tanınan imza bölümleri ve `>` ile başlayan alıntılar bulgularda görünür ve risk birleşimine katılmaz. Bu yaklaşım bağlantısı başka paragrafta olan veya belirgin talep içermeyen saldırıları kaçırabilir.

Bağlantı etiketindeki bir işlem talebi de kendi hedefine bağlanır. Örneğin “Belgeyi görüntülemek için oturum açın” ifadesi, etiketin ait olduğu bağlantıyla birlikte değerlendirilir. Görünen adres ve hedef aynı kaydedilebilir alan adındaysa, fark tek başına riski yükseltmez. Yönlendirme parametresi etiketin gösterdiği adresi aynen içeriyorsa uyuşmazlık görünür kalır, ancak başka bir açıklama olabileceği hesaba katılır. Yönlendirme çalıştırılmaz ve gerçek hedef doğrulanmaz.

Bağlantı hedefleri WHATWG `URL` ayrıştırıcısıyla incelenir. Paketle gelen Public Suffix List verisi, kaydedilebilir alan adını alt alan adından ayırır. Yapısal kontroller kullanıcı bilgisi, IP, Punycode, kısaltıcı, benzer alan adı, başka bir alan adına işaret eden URL parametresi ve çalıştırılabilir dosya uzantılarını kapsar. Düz metin, `hxxps` veya `[.]` gösterimi, basit Markdown ve metin etiketli HTML bağlantıları desteklenir. Zengin biçimden düz metne yapıştırırken gizli hedef kaybolabilir.

Gönderici ve yanıt adresi kontrolü, başta bulunan düz metin başlıklarındaki birer adresin kaydedilebilir alan adını karşılaştırır. Meşru sistemler de ayrı yanıt alan adları kullanabilir. Gönderici kimlik doğrulaması, alan adı itibarı, hedef sayfa içeriği ve gerçek yönlendirmeler kontrol edilmez. Ek dosyalar açılmaz ve QR görselleri okunmaz.

`.eml` dosyaları PostalMime ile cihazda ayrıştırılır. HTML gövde parse5 ile veri olarak okunur. Metin ve gerçek bağlantı hedefleri analiz metnine dönüştürülür. Dış görseller yüklenmez ve HTML çalıştırılmaz. Ekler için yalnızca dosya adı ve dosyada bildirilen tür gösterilir. Gönderenin kimliği doğrulanmaz. Analiz metnini düzenlemek, ekrandaki özgün dosya özetini kaldırır. Varsayılan raporda e-postanın konu, adres ve ek adı gibi alanları yerine gövde biçimi ve ek sayısı yer alır.

Sonuç istatistiksel olasılık yerine uygulanan kuralların özetidir. “Belirgin risk işareti bulunamadı” yalnızca kuralların bir belirti yakalamadığı anlamına gelir. Yeni dil kalıpları, karmaşık bağlantı biçimleri ve bağlam yanlış pozitif veya kaçırılan bulgulara yol açabilir.

Senaryo örnekleri için [FTC kimlik avı rehberi](https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams) ve [FTC SMS rehberi](https://consumer.ftc.gov/articles/how-recognize-and-report-spam-text-messages).

## Gizlilik ve güvenlik

Sonuç ekranındaki **Güvenli sonraki adımlar** bölümü bağımsız doğrulama yolunu ve bulgulara göre hesap, ödeme, cihaz veya QR kodu önlemlerini gösterir. **Mesajla zaten etkileşime geçtiysen** bölümü olası işlemlere göre müdahale adımlarını içerir. Her iki bölüm JSON ve yazdırma raporunda bulunur. [FTC phishing rehberi](https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams) · [FTC müdahale rehberi](https://consumer.ftc.gov/articles/what-do-if-you-were-scammed) · [NCSC müdahale rehberi](https://www.ncsc.gov.uk/collection/phishing-scams/what-to-do)

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

### Gerçek e-posta başlangıç ölçümü (v0.5.0)

Nazario 2025 arşivinden phishing, Apache SpamAssassin `20030228_hard_ham` arşivinden meşru sınıfı için eşit aralıklı 80'er örnek seçildi. Aynı motor, önce HTML'deki görünen metin ve konu ile, sonra özgün dosyadan çıkarılan konu, gövde, başlıklar ve bağlantı hedefleri ile çalıştırıldı. Adres itibarı değerlendirmeye dahil edilmedi. Meşru sınıfta 3 dosya analiz giriş sınırlarına uymadığı için iki taraftan da çıkarıldı. Kaynak etiketleri arşivlere aittir. Setler farklı dönemlerden geldiği ve gerçek Türkçe e-postalar için doğrulanabilir ayrı bir sınıf bulunamadığı için bu sonuç güncel Türkçe trafiğe genellenemez.

| Ölçüm | Görünen metin | Özgün dosya |
| --- | ---: | ---: |
| Artmış veya yüksek risk verilen phishing | 2/80 | 8/80 |
| Artmış veya yüksek risk verilen meşru mesaj | 2/77 | 12/77 |
| Yüksek risk verilen phishing veya meşru mesaj | 0 | 0 |

Özgün dosya 67 phishing ve 52 meşru mesajda ek bağlantı hedefi sağladı. Ek kanıt hem bulunan saldırıları hem de meşru mesajlara verilen uyarıları artırdı.

Tekrar çalıştırmak için [Nazario phishing-2025](https://monkey.org/~jose/phishing/phishing-2025) dosyasını `.evaluation/phishing-2025` yoluna, [Apache hard_ham](https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2) dosyasını `.evaluation/hard-ham.tar.bz2` yoluna kaydet. `tar` komutu kurulu iken `npm run evaluate:email` çalıştır. Komut arşiv özetlerini ve yalnızca toplu ölçümleri yazar. Kaynak mesajlar Git’e girmez. Nazario arşivi José Nazario tarafından CC BY 4.0 koşuluyla yayımlanmıştır. SpamAssassin arşivindeki mesaj hakları özgün gönderenlere aittir. [Nazario arşiv notları](https://monkey.org/~jose/phishing/README.txt) · [SpamAssassin arşiv notları](https://spamassassin.apache.org/old/publiccorpus/readme.html)

### Bağlantı kurallarının karşılaştırması (v0.6.0)

Aynı örneklem sırasındaki çift konumlar geliştirme, tek konumlar ayrı karşılaştırma grubu olarak ayrıldı (sıfır tabanlı). `npm run evaluate:email -- development` ve `npm run evaluate:email -- holdout` komutları her grubun sonuçlarını verir. Aşağıdaki tablo özgün e-postadaki artmış veya yüksek risk eşiğini gösterir.

| Ayrı karşılaştırma grubu | v0.5.0 | v0.6.0 |
| --- | ---: | ---: |
| Uyarı alan phishing | 4/40 | 4/40 |
| Uyarı alan meşru mesaj | 6/40 | 4/40 |

İlk denemede bütün tekil adres uyuşmazlıklarının ağırlığı azaltıldığında phishing uyarıları da kayboldu. Son kural yalnızca aynı alan adı ve açıklanabilir hedef parametresi durumlarını daha temkinli değerlendirir. Ayrı grup aynı arşiv örnekleminden geldiği için bağımsız saha testi sayılmaz. Bu grupta 36 phishing mesajı artmış risk eşiğinin altında kaldı.

- `src/analysis/` girdiyi, kuralları, sonuç tiplerini ve rapor şemasını içerir.
- `src/i18n/` arayüz ve rapor çevirilerini, `src/config.ts` geçici ürün adını ve sınırları tutar.
- `src/main.ts` ve `src/styles.css` ekran ve yazdırma akışını oluşturur.
- `tests/` birim ve tarayıcı senaryolarını kapsar.
