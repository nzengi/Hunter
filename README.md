# Bitcoin Private Key Finder

Arama araçları, Bitcoin Puzzle #73'ü çözmek için belirli bir adres aralığında Bitcoin özel anahtarlarını arayan yüksek performanslı araçlardır.

## Genel Bakış

Bu araçlar, belirli özelliklere sahip Bitcoin adresleri için anahtarlar arar:
- `0x1000000000000000000` ile `0x1ffffffffffffffffff` aralığında
- `12VV` ile başlayan ve `ysn4` ile biten adresler
- Hedef adres: `12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4`
- Public Key Hash: `105b7f253f0ebd7843adaebbd805c944bfb863e4`

## Özellikler

- Çoklu işlemci çekirdeği desteği
- Verimli rasgele arama algoritması
- Gerçek zamanlı istatistikler ve ilerleme takibi
- Eşleşen anahtarları dosyaya kaydetme
- NVIDIA 3060 gibi GPU'lar için optimize edilmiş versiyon (CUDA ile)

## Gereksinimler

- Python 3.6+
- NumPy
- coincurve
- base58

## Yükleme

Python bağımlılıklarını yükle:
```
pip install numpy coincurve base58
```

## Kullanım

### Basit CPU Arayıcı (En Hızlı Başlangıç)

Tek işlemcili basit arayıcıyı çalıştır:

```bash
python simple_bitcoin_finder.py
```

### Çok Çekirdekli CPU Arayıcı

Çoklu işlemci çekirdeği kullanan optimizasyonlu arayıcıyı çalıştır:

```bash
python optimized_bitcoin_finder.py
```

### GPU Hızlandırmalı Arayıcı (CUDA Desteği Gerektirir)

CUDA destekli GPU arayıcıyı çalıştır:

```bash
python bitcoin_puzzle_solver.py
```

## Terminal Çıktısı

Programlar çalıştığında, şu bilgileri göreceksiniz:
- Kontrol edilen anahtar sayısı
- Saniyede kontrol edilen anahtar hızı
- Tahmini tamamlanma süresi
- İlerleme yüzdesi

Örnek:
```
Keys checked: 1,090,807 @ 14,161/sec | Elapsed: 1.3 min | Progress: 0.000000000000% | ETA: 3859666706358.7 days
```

## Eşleşme Bulunduğunda

Bir eşleşme bulunduğunda, program şunları gösterecektir:
- Bulunan Bitcoin adresi
- Özel anahtar (hex formatında)
- Public Key Hash
- Tam eşleşme veya desen eşleşmesi olduğu bilgisi

Tüm eşleşmeler otomatik olarak `found_matches.json` dosyasına kaydedilir.
