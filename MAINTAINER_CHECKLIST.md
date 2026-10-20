# Yayın öncesi güven kontrol listesi

Bu liste, kodun dışında kalan ve yalnızca sizin yapabileceğiniz adımları içerir. Kod tarafındaki güvenceler (ağ yok, salt okunur, maskeli çıktı, sıfır bağımlılık) testlerle zaten sağlanıyor.

## 1. Hesap güvenliği (lansmandan önce, zorunlu)

- [ ] GitHub hesabında iki adımlı doğrulamayı açın; mümkünse passkey veya donanım anahtarı kullanın.
- [ ] npmjs.com hesabı açın ve iki adımlı doğrulamayı **"Authorization and writes"** düzeyinde açın.
- [ ] Bu hesaplarda kullandığınız e-postanın da iki adımlı doğrulaması açık olsun.

## 2. Repo kurulumu

- [ ] GitHub'da `keyleakcheck` adlı public repo oluşturun ve bu klasörü yükleyin.
- [x] `OWNER` yer tutucuları `synthmodulelab` ile değiştirildi.
- [ ] **Settings → Code security → Private vulnerability reporting** özelliğini açın.
- [ ] **Settings → Branches** altında `main` için koruma kuralı ekleyin: pull request zorunlu, CI geçmeli, force push kapalı.
- [ ] **Settings → Environments** altında `npm-publish` ortamını oluşturun ve kendinizi "required reviewer" yapın. Böylece her yayın sizin onayınızı bekler.

## 3. Yayın altyapısı

- [x] npm'de **Trusted Publishing** kuruldu (repo `synthmodulelab/keyleakcheck`, iş akışı `release.yml`, ortam `npm-publish`). Paket ayarında token ile yayın kapalı. Eski token ve `NPM_TOKEN` secret'ı silindi; yeni token oluşturmayın.
- [x] Action'lar tam commit SHA'larına sabitlendi; Dependabot (`.github/dependabot.yml`) aylık güncelleme önerir. Dependabot PR'larında SHA'nın resmi etiketle eşleştiğini kontrol edip birleştirin.
- [ ] İsteğe bağlı: OpenSSF Scorecard iş akışını ekleyip README'ye rozetini koyun. Güvenlik meraklıları buna bakar.

## 4. Gerçek ortamda test

- [ ] Aracı kendi macOS, Windows veya Linux makinenizde, gerçekten kullandığınız ajanlarla çalıştırın.
- [ ] `--list-locations` çıktısında ✔ görünmesi gereken ama görünmeyen yolları not edin ve düzeltin. Ajan dosya yolları sürüm sürüm değişebiliyor.
- [ ] Gerçek bir anahtarı test için kullanmayın; test dosyalarındaki sahte anahtar üreticisini kullanın.

## 5. Bağımsız inceleme (en önemli güven adımı)

- [ ] Güvendiğiniz bir veya iki geliştiriciden kodu incelemesini isteyin. Kod yaklaşık 1.000 satır (önemli bir kısmı açıklama ve konum listesi); 45-60 dakikalık bir iş.
- [ ] İncelemeyi yapan kişi izin verirse README'ye adını ekleyin. İzin almadan isim yazmayın.

## 6. İsim ve hukuk

- [ ] Benzer adlı sahte paketlere karşı npm'de adınızı düzenli kontrol edin; şüpheli paketi npm'e bildirin.
- [ ] Ücretli sürümü açmadan önce kullanım şartlarını ve iade politikasını bir hukukçuya gösterin.

## 7. Ürün yapısı: iki paket

Ürün iki ayrı paketten oluşur. Bu ayrım güvenin temelidir, bozulmamalıdır.

| | `keyleakcheck` (bu repo, ücretsiz) | `keyleakcheck-fix` (Pro, ayrı repo) |
| --- | --- | --- |
| Ağ erişimi | Hiç yok | Yalnızca canlılık kontrolünde, yalnızca izin listesindeki resmi sağlayıcı API adreslerine, her seferinde onayla |
| Dosya yazma | Hiç yok | Yalnızca maskelemede; önizleme, onay ve zaman damgalı yedekten sonra, tek komutla geri alınabilir |
| Özellikler | Tarama, maskeli rapor, kurtarma rehberi, skor kartı, JSON, CI ve pre-commit kullanımı | Canlılık kontrolü, otomatik maskeleme, bekçi modu ve masaüstü bildirimi |

Kurallar:

- [ ] Ağ erişimi veya dosya yazma gerektiren hiçbir özellik bu repoya eklenmez. `test/guarantees.test.js` buna izin vermez; testi gevşetmek yerine özelliği `keyleakcheck-fix`'e koyun.
- [ ] `keyleakcheck-fix` kendi `SECURITY.md` dosyasında kendi güvencelerini yazar ve bunları kendi testleriyle korur: sabit adres izin listesi, her ağ isteği ve her dosya değişikliği öncesi onay, değişiklik öncesi yedek, telemetri yok.
- [ ] Çekirdek paket `keyleakcheck-fix`'e bağımlı olmaz; onsuz eksiksiz çalışır.
- [ ] Pazarlamada iki paket hiçbir zaman karıştırılmaz: "ağa hiç bağlanmaz" ifadesi yalnızca çekirdek araç için kullanılır.
