# Damn Vulnerable Web Services

## Aplikacja
Aplikacja Damn Vulnerable Web Services to podatna na ataki usługa internetowa i interfejs API, której można użyć do poznania luk w zabezpieczeniach związanych z usługami sieciowymi/API.
Instalacja aplikacji przebiega za pomocą dockera. Wystarczy wywołać polecenie:
```
`docker-compose up`
```
Na koniec nalezy w pliku /etc/hosts podmienić nazwę localhost dla adresu 127.0.0.1 na wybraną nazwę aplikacji.

Aplikacja webowa została napisana w JavaScript.

## WERSJE OPROGRAMOWANIA

Tested on:
* node v10.19.0
* npm 6.13.7
* mongodb 4.0.4


## TESTY ZABEZPIECZEŃ

1. Hashowanie haseł

    Hasła są zaszyfrowane
    ![password hashing](resources/password.png)

2. XML External Entity Injection (XXE)

    Jest to Wstrzyknięcie podmiotu zewnętrznego XML (znane również jako XXE) to luka w zabezpieczeniach sieci Web, która umożliwia osobie atakującej ingerowanie w przetwarzanie danych XML przez aplikację. Często umożliwia atakującemu przeglądanie plików w systemie plików serwera aplikacji i interakcję z dowolnymi systemami zaplecza lub systemami zewnętrznymi, do których sama aplikacja ma dostęp.
    Biblioteka XML używana przez serwer SOAP do analizowania tego żądania umożliwia korzystanie z jednostek zewnętrznych. W związku z tym można to wykorzystać do odczytu dowolnych plików z usługi SOAP.
   ![xxe](resources/xxe.png)

3. Server Side Request Forgery (SSRF)

    ![ssrf](resources/ssrf.png)

4. User Enumeration

* tworze uzytkownika
    ![new user](resources/create-user.png)
* sprawdzam jaka jest odpowiedź serwera gdy on istnieje
    ![test if user exist](resources/test-user.png)


* sprawdzenie uzytkownika moze odbywac sie tez za pomoca xml
    ![test if user exist](resources/test-user1.png)

    mając taką odpowiedź, hacker moze teraz za pomocą techniki brute force sforsować hasło uytkownika

5. NoSQL Injection - pozyskanie danych za pomocą zapytania do bazy
    Dzięki temu mozna było pozyskać wszystkie dostępne notatki, nawet te, które nie są publiczne.
    ![nosql](resources/nosql.png)

6. Insecure Direct Object Reference
    ![idor](resources/idor.png)

7. Mass Assignment

8. XML Cross-Site Scripting (XSS)
    ![xss](resources/xss.png)
    ![xss2](resources/xss2.png)
    ![xss3](resources/xss3.png)

9. Hidden API Functionality Exposure
    Po uruchomieniu swaggera widać rózne dostępne endpointy. Wpisując w przeglądarkę po kolei kazdy endpoint, sprawdzane jest, czy sa on zabezpieczone.

    ![api](resources/api.png)


10. SQL Injection

11. Information Disclosure
* uzytkownikowi po zalogowaniu zwracane sa zszyfrowane haslo




12. Command Injection
    ![cm0](resources/cm0.png)
    ![cm1](resources/cm1.png)


13. JSON Hijacking

    Kradzież tych informacji jest możliwa z następujących powodów:

    Dane są zwracane z typem zawartości Content-Type: application/json (nie określono zestawu znaków)
    Dane są zwracane wewnątrz tablicy [].
    Do wykonania powyższego żądania nie jest wymagane żadne uwierzytelnienie (problem z kontrolą dostępu)
    Uwaga: w większości nowoczesnych przeglądarek usunięto problem przechwytywania JSON

    ![hijack](resources/hijack.png)

14. XPath Injection ????

15. Cross Origin Resource Sharing Misonfiguration ???


16. JWT Secret Key Brute Force

    Uzytkownikowi po zalogowaniu zwracany jest token jwt. Token ten mozna sprobowac rozszywrowac uzywajac roznych narzedzi jak np. jwt-cracker.
    ![jwt](resources/jwt.png)
    ![jwt-crack](resources/jwt-crack.png)

