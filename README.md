# Mesaj Kontrolü

Türkçe ve İngilizce mesaj, e-posta ve sosyal medya metinlerinde yaygın phishing belirtilerini açıklayan, tarayıcıda çalışan bir ön kontrol aracı. Uygulamanın ve JSON şemasının sürümleri ayrı tutulur. İlk uygulama sürümü `0.1.0`, analiz yöntemi `local-phishing-rules 1.0.0`, JSON şeması `1`.

## Yerelde çalıştırma

Node.js 22.18+ ve npm gerekir. İlk kurulum bağımlılıkları indirir. Uygulama çalışırken API anahtarı, ortam değişkeni veya internet bağlantısı gerekmez.

```sh
npm ci
npm run dev
```

[Yerel uygulamayı aç](http://127.0.0.1:4173). `npm run dev`, sıkı içerik güvenlik politikasıyla uyumlu üretim çıktısını oluşturur ve yerelde sunar. Kaynak değiştiğinde yeniden başlat. `npm run build` statik çıktıyı `dist/` dizinine yazar. `npm run preview` mevcut çıktıyı sunar.

## Kullanım

1. Türkçe veya İngilizce arayüzü seç. İki dildeki kurallar her analizde birlikte çalışır.
2. Mesajı yapıştır veya UTF-8 `.txt` dosyası seç. Sınırlar 20.000 Unicode kod noktası ve 100 KB (100.000 bayt).
3. **Analiz et** ile gerekçeleri, metindeki vurguları, bağlantı bulgularını ve uygulanamayan kontrolleri incele.
4. İstersen **JSON indir** veya **Yazdır / PDF olarak kaydet** düğmesini kullan. Özgün metin, alıntı ve tam URL eklemek için rapordaki seçeneği ayrıca işaretle.
5. **Temizle** ile bu sekmedeki metni ve sonucu kaldır.

## Analiz yaklaşımı ve sınırlar

Yerel ifade kuralları zaman baskısı, hassas veri talebi, ödeme, ödül ve kimlik iddiası arar. Açık uyarı ve alıntı bağlamları bulguların ağırlığını düşürür. Tekrarlanan göstergeler yeni risk kategorileri oluşturmaz. Yüksek risk için hassas bilgi ya da ödeme talebinin başka türden göstergelerle birleşmesi gerekir.

Bağlantı hedefleri WHATWG `URL` ayrıştırıcısıyla incelenir. Paketle gelen Public Suffix List verisi, kaydedilebilir alan adını alt alan adından ayırır. Yerel örüntüler kullanıcı bilgisi, IP adresi, Punycode, kısaltıcı ve sınırlı bir kurum listesine dayanan alan adı benzerliklerini işaretler. Düz metindeki URL’ler, basit Markdown bağlantıları ve metin etiketli HTML çapaları desteklenir. Zengin biçimden düz metne yapıştırırken gizli hedef kaybolabilir. Yalnızca URL girilirse mesaj dili kontrol edilemez. Hedef içerik, itibar ve yönlendirmeler incelenmez.

Sonuç istatistiksel olasılık yerine uygulanan kuralların özetidir. “Belirgin risk işareti bulunamadı” yalnızca kuralların bir belirti yakalamadığı anlamına gelir. Yeni dil kalıpları, karmaşık bağlantı biçimleri ve bağlam yanlış pozitif veya kaçırılan bulgulara yol açabilir. Bu araç sınırlı kapsamlı bir ön kontroldür. AI üretimi, iddia doğruluğu ve kaynak/köken ayrı kontrollerdir ve bu sürümde değerlendirilemez. İçeriğin AI ile üretilen payı çoğu durumda ölçülemez.

## Gizlilik ve güvenlik

Mesaj, dosya ve analiz uygulama tarafından yalnızca açık sekmenin belleğinde tutulur. Analiz ağ isteği başlatmaz. Uygulama kullanıcı içeriğini günlüklere, kalıcı tarayıcı depolarına veya analitik sistemlerine yazmaz. Kullanıcı içeriği metin olarak gösterilir ve incelenen URL’ler tıklanabilir değildir. Statik çıktının içerik güvenlik politikası ağ bağlantılarını, harici kaynakları ve form gönderimlerini engeller.

Varsayılan raporlar yalnızca bulgu kategorilerini ve açıklamalarını içerir. İçerik ekleme seçeneği özgün metni, alıntıları ve tam URL’leri iki rapor biçimine de dahil eder. Bu alanlar hassas veri içerebilir. İndirilen veya yazdırılan kopyalar tarayıcı ve kullanıcının seçtiği cihaz konumları tarafından yönetilir.

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

- `src/analysis/` girdiyi, kuralları, sonuç tiplerini ve rapor şemasını içerir.
- `src/i18n/` arayüz ve rapor çevirilerini, `src/config.ts` geçici ürün adını ve sınırları tutar.
- `src/main.ts` ve `src/styles.css` ekran ve yazdırma akışını oluşturur.
- `tests/` birim ve tarayıcı senaryolarını kapsar.

## Sonraki fazlar

1. Fotoğraflarda metadata ve doğrulanabilir köken. Metadata eksikliği AI üretimini, geçerli köken de iddiaların doğruluğunu tek başına kanıtlamaz.
2. Seste sentetik üretim ve manipülasyon belirtileri. Dil, süre ve maliyet sınırları ayrıca değerlendirilir.
3. Videoda kare, ses ve zaman içindeki değişimler. Birkaç kareden tüm video hakkında kesin hüküm verilmez.

Faz sırası maliyet ve uygulanabilirliğe göre değişebilir. Gerçek AI metin tespiti ve kaynak destekli iddia doğrulama ayrı araştırma başlıklarıdır. Sağlayıcı eklemek için `ProviderAssessment` ortak sonuç biçimi sağlar. Harici işlemden önce veri aktarımı ve saklama koşulları açıklanmalı. Sunucu tarafında URL erişiminin ön koşulu SSRF korumasıdır. LLM entegrasyonunda incelenen içeriğin içindeki talimatlar güvenilmeyen veri olarak ele alınmalıdır.
