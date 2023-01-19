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


## Audyt

Audyt bezpieczeństwa został zrealizowany zgodnie ze standardem OWASP Top 10 oraz pod kątem ogólnego bezpieczeństwa. Badana aplikacja wykazała wiele podatności na ataki, więc przed udostępnieniem jej szerzej nalezałoby ją odpowiedno zabezpieczyć. Aplikacja ma bardzo niski poziom zabezpieczeń, skupiający się głównie na szyfrowaniu haseł uzytkownika. Dane uzytkownika nie sa w zadnym stopniu chronione.

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

Atak polega na przypisywaniu wartości zmiennej po stronie serwera.
Przykłądem jest tworzenie użytkownika bez uprawnień adminstratora. 
W tym przypadku defaultowy obiekt użytkownika zostaje utworzony ze zmienną admin=false.
Atak będzie polegał na narzuceniu zmiennej admin=true i jednoczesnym przejęciu uprawnień administratora.
![mass-assignment](resources/mass-assignment.png)
![mass-assignment2](resources/mass-assignment2.png)
![mass-assignment3](resources/mass-assignment3.png)

8. XML Cross-Site Scripting (XSS)
    ![xss](resources/xss.png)
    ![xss2](resources/xss2.png)
    ![xss3](resources/xss3.png)

9. Hidden API Functionality Exposure
    Po uruchomieniu swaggera widać rózne dostępne endpointy. Wpisując w przeglądarkę po kolei kazdy endpoint, sprawdzane jest, czy sa on zabezpieczone.

    ![api](resources/api.png)


10. SQL Injection
Ataki SQL Injection są niestety bardzo powszechne, a wynika to z dwóch czynników:
znaczne rozpowszechnienie luk SQL Injection oraz atrakcyjność celu (tj. baza danych zazwyczaj zawiera wszystkie interesujące/krytyczne dane dla Twojej aplikacji). Wstrzyknięcia SQL są wprowadzane, gdy twórcy oprogramowania tworzą dynamiczne zapytania do bazy danych zbudowane z konkatenacji łańcuchów, które obejmują dane wejściowe wprowadzone przez użytkownika. Może to zostać wykorzystane do przeglądania, modyfikowania lub usuwania danych aplikacji, co wcześniej nie było możliwe, lub do powodowania trwałych zmian w zawartości lub zachowaniu aplikacji.

Uniknięcie błędów iniekcji SQL jest proste. Deweloperzy muszą albo: 
a) przestać pisać dynamiczne zapytania z konkatenacją łańcuchów;
i/lub
b) zapobiegać wpływaniu danych wejściowych użytkownika, które zawierają złośliwy kod SQL, na logikę wykonywanego zapytania.

Poniżej przeprowadzono atak polegający na wstrzyknięciu w URL dodatkowego znaku ' po nazwie użytkownika.
Przed atakiem:


![sql1_1](resources/sql1_1.png)

Atak:

![sql_injection1](resources/sql_injection1.png)


Po ataku:

![sql_injection2](resources/sql_injection2.png)


Kolejny atak polegał na podmienieniu nazwy użytkownika na frazę '1'='1
![sql4](resources/sql4.png)
![sql5](resources/sql5_2.png)




11. Information Disclosure

    Ujawnienie informacji, znane również jako wyciek informacji, ma miejsce, gdy witryna internetowa nieumyślnie ujawnia użytkownikom poufne informacje. W zależności od kontekstu strony internetowe mogą ujawnić potencjalnemu atakującemu wszelkiego rodzaju informacje, w tym: dane o innych użytkownikach, takie jak nazwy użytkowników.

    Zwrocono uwage, ze testowana aplikacja ujawnia dane odnosnie:
* zszyfrowanego hasla, które jest zwracane uzytkownikowi po zalogowaniu 
* wyswietlany jest zbedny naglowek x-powered informujący, ze Express jest w uzytku

    ![id](resources/id.png)

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

15. Cross Origin Resource Sharing

    CORS to mechanizm, który zapewnia mozliwość bezpiecznej wymiany danych pomiędzy stronami, które charakteryzuje inny Origin.
    Istnieją dwa główne rodzaje błędnych konfiguracji CORS, które mogą narazić serwer WWW na ataki CORS:

 * Access-Control-Allow-Origin (ACAO): Umożliwia dwukierunkową komunikację z witrynami stron trzecich.  Błędna konfiguracja Access-Control-Allow-Origin (ACAO) może zostać wykorzystana do modyfikowania lub przekazywania poufnych danych, takich jak nazwy użytkowników i hasła.
 *Access-Control-Allow-Credentials (ACAC): Umożliwia stronom internetowym stron trzecich wykonywanie uprzywilejowanych działań, które powinien być w stanie wykonać tylko autentycznie uwierzytelniony użytkownik.  Przykładem może być zmiana hasła lub informacji kontaktowych.

    Dla badanej aplikacji zauwazono ze parametr ACAC ustawiony jest na true, przez co aplikacja jest narazona na ataki CORS. Po wysłaniu z innej strony ządania dostępu do zasobu mozna np uzyskac informacje o wygenerowanych hasłach uzytkownikow, które nie sa zabezpieczone (kazdy z zewnatrz moze je podejrzec wpisujac odpowiedni adres url).
    ![cors](resources/cors.png)

16. JWT Secret Key Brute Force

    Uzytkownikowi po zalogowaniu zwracany jest token jwt. Otrzymany token mozna wrzucic na stronę jwt.io, która m.in. ujawnia algorytm szyfrujący. Token ten mozna sprobowac rozszywrowac uzywajac roznych narzedzi jak np. jwt-cracker.

    ![jwtio](resources/jwtio.png)
    ![jwt](resources/jwt.png)
    ![jwt-crack](resources/jwt-crack.png)


15. Vertical Access Control

Pionowa eskalacja uprawnień jest możliwa, jeśli klucz kontrolowany przez użytkownika jest w rzeczywistości  flagą wskazującą status administratora, umożliwiając atakującemu uzyskanie dostępu administracyjnego.

Wiele wywołań interfejsu API, które może wykonać tylko administrator w obszarze administracyjnym, może wywołać użytkownik bez uprawnień administratora.

Po zalogowaniu na zwykłego użytkownika, wchodzimy w panel z danymi dla admina. Rozpoczyna się sprawdzanie uprawnień:
![VAC1_](resources/VAC1_.png)

Atak polega na podmienieniu URL:

![VAC2_](resources/VAC2_.png)

Użytkownik bez uprawnień administratora uzyskał dostęp do panelu admina:
![VAC3](resources/VAC3.png)

Sprawdzenie możliwość korzystania z panelu i wyszukanie innego użytkownika:

![VAC4](resources/VAC4.png)
![VAC5](resources/VAC5.png)

16. Horizontal Access Control

Możliwa pozioma eskalacja uprawnień (jeden użytkownik może przeglądać/modyfikować informacje innego użytkownika.
Możliwe jest przeglądanie haseł utworzonych przez użytkownika, jeśli znasz nazwę użytkownika
Możliwe jest przeprowadzenie ataku nie tylko za pomoca podmiany nazwy użytkownika, ale także podmiany ID

Utworzenie rekordu danych dla użytkownika z uprawnieniami administratora.

![HAC1](resources/HAC1.png)

Zalogowanie na zwykłego użytkownika Marcin oraz podmiana nazwy użytkownika na tego z uprawnieniami administratora.

![HAC2](resources/HAC2.png)

Dostęp do passphare administratora :

![HAC3](resources/HAC3.png)

17. Open Redirect
18. Path Traversal
19. Unsafe Deserialization
20. Sensitive Data Exposure