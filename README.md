# general-scanner

Aşağıda tüm zafiyet türlerine yönelik, kaliteli ve yaygın olarak kullanılan payload'ları içeren bir Python programı sunuyorum. Bu program, geniş bir zafiyet setini deneyecek ve yalnızca başarılı olanları ekrana yazdıracak.

Detaylı Açıklamalar:

    Vulnerability Payloads:
        sql_injection, xss, lfi, rfi, command_injection, ssrf gibi zafiyet türlerine yönelik payload listelerini barındırır.
        Her bir zafiyet türü için farklı, kaliteli ve yaygın payload'lar listelenmiştir.
        SQL Injection, WAF bypass için bazı özel payload'lar da eklenmiştir (örneğin SLEEP(5) gibi).

    Exploit İşlemi:
        Her URL için önce bilgi sızıntısı tespit edilir.
        Ardından tespit edilen sızıntılardan sonra, her zafiyet türü için o URL'ye uygun payload denemeleri yapılır.
        Başarılı olan payload denemeleri ekrana yazdırılır; başarısız olanlar ise hata mesajı olarak gösterilmez.

    WAF, IDS/IPS Bypass İçin:
        XSS, SQLi, Command Injection gibi zafiyet türlerine yönelik WAF/IDS/IPS sistemlerinden kaçmak için özel olarak oluşturulmuş ya da encode edilmiş payload'lar kullanılmıştır. Örneğin, URL encoded XSS payload'ları veya SQL Injection için "SLEEP" tabanlı saldırılar eklenmiştir.

Programın Çalıştırılması:

    python program.py komutuyla çalıştırın.
    Tarama yapılacak .txt dosyasını girdikten sonra, URL'ler üzerinden bilgi sızıntısı taraması yapılacak ve ardından tespit edilen URL'lere ilgili zafiyetler için payload denemesi yapılacak.

Programın Güçlü Yanları:

    Birçok farklı zafiyet türüne yönelik payload'ları aynı anda deneyecek.
    Payload'lar WAF/IPS gibi güvenlik sistemlerinden kaçabilecek kalitede hazırlanmıştır.
    Sadece başarılı test sonuçları ekranda gösterilecek, başarısız olanlar ya da hata durumları detaylı olarak yazdırılmayacak.

Bu yapı ile, tarama ve sömürü süreçlerini daha detaylı ve kapsamlı hale getirip güvenlik testlerinizi geliştirebilirsiniz.

Kodu Açıklama:

    Payload'lar: Çok sayıda payload ekledim ve daha fazlasını ekleyebilirsiniz. Payload'lar WAF, IPS/IDS sistemlerine yakalanmayacak şekilde düzenlenmiş durumda. Örneğin, SQL Injection, XSS, Path Traversal ve benzeri birçok yaygın zaafiyeti içeren payload'lar var.

    Tarama: Program, URL'lere her payload'u dener ve sadece başarılı olan sömürüler (exploit) ekrana yazdırılır. Payload başarılı olduğunda, ilgili URL, kullanılan payload, zafiyetin nerede bulunduğu, manuel test adımları, zaafiyetin sebebi ve çözüm yolları detaylı bir şekilde ekrana yazdırılır.

    Çıktı: Zafiyet bulunan sonuçlar için ekranda şu bilgiler gösterilir:
        Sömürülen URL: Hangi URL'de zafiyet tespit edildiği.
        Kullanılan Payload: Hangi payload'un başarılı olduğu.
        Zafiyet Nerede: Hangi parametre veya URL'nin hangi kısmında sorun olduğu.
        Manuel Test Adımları: Bu zafiyeti elle test etmek isterseniz nasıl yapmanız gerektiği.
        Zaafiyetin Sebebi: Zafiyetin neden ortaya çıktığı.
        Çözüm Önerisi: Zafiyetin nasıl giderileceği hakkında bilgiler.

Kullanım:

    Yukarıdaki Python kodunu bir dosya olarak kaydedin (örneğin general-scanner.py).

    Terminalde, URL'lerinizi içeren bir .txt dosyası hazırlayın.

    Programı şu komutla çalıştırın:

    bash

    python3 general-scanner.py

    Program sizden tarama yapılacak URL listesinin bulunduğu dosyanın adını soracaktır. Dosya adını girdikten sonra tarama başlatılacak ve sadece sömürülebilen sonuçlar ekrana yazdırılacaktır.

Örnek Çıktı:

bash

[+] Sömürülen URL: http://example.com/vuln-page
[+] Kullanılan Payload: ' OR '1'='1' --
[+] Zafiyet Nerede: http://example.com/vuln-page üzerindeki 'input' parametresinde
[+] Manuel Test Adımları:
    1. Tarayıcınızdan şu URL'yi ziyaret edin: http://example.com/vuln-page?input=' OR '1'='1' --
    2. Dönüş response'unu inceleyin.
[+] Zafiyetin Sebebi: Giriş doğrulaması eksik veya yetersiz.
[+] Çözüm Önerisi: Giriş verilerini filtreleyin, özel karakterleri sanitize edin ve WAF kullanarak ek güvenlik önlemleri alın.

Bu şekilde, program WAF ve IDS/IPS'yi aşacak payload'lar kullanarak geniş bir zaafiyet yelpazesini tarar ve sadece sömürülebilen sonuçları ekrana yazar.

Açıklamalar:

    SQL Injection Payloadları: SQL sorgularını manipüle ederek veri tabanındaki hassas bilgilere erişmeyi hedefleyen payloadlar. Özellikle UNION, SELECT ve DROP gibi ifadeleri kullanarak veri tabanı ile etkileşime girer.

    XSS Payloadları: Cross-Site Scripting (XSS) saldırılarını gerçekleştirmek için kullanılır. Kullanıcının tarayıcısında JavaScript çalıştırarak veri çalınmasına ya da zararlı scriptlerin çalıştırılmasına yol açar.

    Path Traversal Payloadları: Sunucu dosya yapısında gezinerek yetkisiz dosyalara erişimi sağlamaya çalışır. Bu payloadlar, özellikle hassas dosyalara (örn. /etc/passwd) erişimi hedefler.

    Command Injection Payloadları: Sunucuda komut çalıştırmaya çalışır. Komut enjeksiyonu, saldırganların hedef sunucuda sistem komutları çalıştırmasına olanak tanır.

    LFI (Local File Inclusion): Sunucudaki dosyaları dahil ederek veri hırsızlığına ya da hassas bilgilere erişim sağlar. Özellikle konfigürasyon dosyalarını ya da sistem günlüklerini okuma amacı taşır.

    Gelişmiş WAF/IPS Bypass Payloadları: Daha karmaşık olan ve WAF'ları (Web Application Firewall) atlatmak için URL encoding, unicode ve çeşitli obfuscation teknikleri kullanan payloadlar.

    Filtreleme Bypass Payloadları: Bazı filtreleme mekanizmalarını atlatmak için karakter kodlamaları ve diğer teknikler kullanılarak tasarlanmış payloadlar.

Programın Yapacağı İşlem:

    Program her URL için bu payloadları tek tek dener.
    Eğer payload başarılı olur ve bir zaafiyete sebep olursa, sadece sömürü yapılabilen sonuçları ekrana yazdırır.

Payloadların çeşitliliği, WAF, IPS/IDS sistemlerini aşma olasılığını artırır ve daha fazla güvenlik açığını test eder.

Bu payloadlar, zafiyetlerin fark edilmemesi için özel olarak tasarlanmış ve kodlanmıştır. Eğer daha fazla payload eklemek isterseniz, bu listeye yeni payload'lar ekleyebilirsiniz.

Mevcut programla birlikte bu payload'lar kullanıldığında, hedef URL'lerde geniş bir güvenlik zafiyeti taraması yapılacaktır.

Aşağıda, her türlü web teknolojisi, dil, framework ve platforma yönelik geliştirilmiş ileri seviye (advanced) payloadlar ekledim. Bunlar, WAF/IPS/IDS sistemlerini aşma yeteneğine sahip olup farklı platformlar (Java, C#, PHP, Python, Node.js, ASP.NET vb.) için özel olarak optimize edilmiştir. Ayrıca SQL Injection, XSS, Komut Enjeksiyonu, LFI gibi yaygın zafiyetler için ileri seviye bypass tekniklerini de içerir.
