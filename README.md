# Kimlik Avı Kontrolü

Türkçe ve İngilizce e-posta, SMS ve bağlantılardaki kimlik avı belirtilerini açıklayan, tarayıcıda çalışan bir ön kontrol aracı. Uygulama sürümü `0.2.0`, analiz yöntemi `local-phishing-rules 2.0.0`, JSON şeması `2`. Yeni JSON şeması risk gerekçesini ve gönderici kontrollerinin kapsamını içerir.

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

Bağlantı hedefleri WHATWG `URL` ayrıştırıcısıyla incelenir. Paketle gelen Public Suffix List verisi, kaydedilebilir alan adını alt alan adından ayırır. Yapısal kontroller kullanıcı bilgisi, IP, Punycode, kısaltıcı, benzer alan adı, başka bir alan adına işaret eden URL parametresi ve çalıştırılabilir dosya uzantılarını kapsar. Düz metin, `hxxps` veya `[.]` gösterimi, basit Markdown ve metin etiketli HTML bağlantıları desteklenir. Zengin biçimden düz metne yapıştırırken gizli hedef kaybolabilir.

Gönderici ve yanıt adresi kontrolü, başta bulunan düz metin başlıklarındaki birer adresin kaydedilebilir alan adını karşılaştırır. Meşru sistemler de ayrı yanıt alan adları kullanabilir. Gönderici kimlik doğrulaması, alan adı itibarı, hedef sayfa içeriği ve gerçek yönlendirmeler kontrol edilmez. Ek dosyalar açılmaz ve QR görselleri okunmaz.

Sonuç istatistiksel olasılık yerine uygulanan kuralların özetidir. “Belirgin risk işareti bulunamadı” yalnızca kuralların bir belirti yakalamadığı anlamına gelir. Yeni dil kalıpları, karmaşık bağlantı biçimleri ve bağlam yanlış pozitif veya kaçırılan bulgulara yol açabilir.

Senaryo örnekleri için [FTC kimlik avı rehberi](https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams) ve [FTC SMS rehberi](https://consumer.ftc.gov/articles/how-recognize-and-report-spam-text-messages).

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
