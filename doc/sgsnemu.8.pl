
.\" * OpenGGSN - Gateway GPRS Support Node
.\" * Copyright (C) 2002, 2003 Mondru AB.
.\" * Polish translation copyright (C) 2004 Marek ¯akowicz <mazaczek@users.sourceforge.net>
.\" * 
.\" * The contents of this file may be used under the terms of the GNU
.\" * General Public License Version 2, provided that the above copyright
.\" * notice and this permission notice is included in all copies or
.\" * substantial portions of the software.
.\" * 
.\" * The initial developer of the original code is
.\" * Jens Jakobsen <jj@openggsn.org>
.\" * 
.\" * Contributor(s):
.\" * 
.\" * Translation to polish: Marek Zakowicz <mazak@debian.linux.org.pl>
.\" Manual page for ggsn
.\" SH section heading
.\" SS subsection heading
.\" LP paragraph
.\" IP indented paragraph
.\" TP hanging label

.TH sgsnemu 8 "Maj 2004"
.SH NAZWA
sgsnemu \- Emulator Wêz³a Dostarczaj±cego Us³ug GPRS
.SH U¯YTKOWANIE
.B sgsnemu
\-\-help

.B sgsnemu
\-\-version

.B sgsnemu
[
.BI \-\-debug
] [
.BI \-\-conf " plik"
] [
.BI \-\-pidfile " plik"
] [
.BI \-\-statedir " plik" 
] [ 
.BI \-\-dns " host"
] [ 
.BI \-\-listen " host" 
] [
.BI \-\-remote " host"
] [
.BI \-\-contexts " liczba"
] [
.BI \-\-timelimit " sekundy" 
] [
.BI \-\-gtpversion " wersja"
] [
.BI \-\-apn " apn"
] [
.BI \-\-selmode " tryb"
] [
.BI \-\-imsi " imsi"
] [
.BI \-\-nsapi " nsapi"
] [
.BI \-\-msisdn " msisdn"
] [
.BI \-\-qos " qos"
] [
.BI \-\-charging " op³ata"
] [
.BI \-\-uid " uid"
] [
.BI \-\-pwd " pwd"
] [
.BI \-\-createif
] [
.BI \-\-net " sieæ" 
] [
.BI \-\-defaultroute
] [
.BI \-\-ipup " skrypt" 
] [
.BI \-\-ipdown " skrypt" 
] [
.BI \-\-pinghost " host"
] [
.BI \-\-pingrate " liczba"
] [
.BI \-\-pingsize " liczba"
] [
.BI \-\-pingcount " liczba"
]
.SH OPIS
.B sgsnemu
jest czê¶ci± projektu
.B OpenGGSN
i implementuje emulator wêz³a dostarczaj±cego us³ug GPRS (SGSN).
Mo¿e on byæ wykorzystywany zarówno do testowania wêz³ów GGSN,
jak rdzenia sieci GRPS, czy po³±czeñ odwiedzaj±cych. 

Funkcjonalno¶æ i protoko³y GPRS zosta³y ustandaryzowane w ramach projektu 
Third Generation Partnership Project (3GPP).
Wed³ug specyfikacji 3GPP, SGSN posiada kilka interfejsów.
.B sgsnemu
implementuje interfejs Gn/Gp, który jest wykorzystywany w kierunku
wêz³ów GGSN.

Interfejs Gn/Gp mo¿e byæ postrzegany jako ³±cze nadrzêdne wêz³a SGSN.
Jest ono wykorzystywane do komunikacji z wêz³em GGSN, który zazwyczaj jest
pod³±czony do Internetu.
Interfejs Gn/Gp wykorzystuje protokó³ tunelowania GPRS (GTP).
Pakiety u¿ytkownika (zazwyczaj pakiety IP) s± tunelowane za po¶rednictwem protoko³u GTP,
który z kolei wykorzystuje protokó³ UDP nad IP.


.B sgsnemu 
ustanawia pewn± liczbê po³±czeñ do GGSN.
Wewnêtrzny ping transmituje ¿±dania ICMP poprzez ju¿ ustanowione po³±czenia.
Alternatywnie, mo¿e byæ utworzony lokalny interfejs sieciowy.
W tym przypadku
.B sgsnemu
przekazuje pakiety pomiêdzy lokalnym interfejsem sieciowym i po³±czeniami
ustanowionymi na interfejsie Gn/Gp.

.B sgsnemu
wykorzystuje sterownik
.B TUN/TAP
jako interfejs lokalny.  Interfejs sieci tun jest ustanawiany dla ka¿dego
po³±czenia zestawianego z wêz³em GGSN.
B³êdy wystêpuj±ce podczas pracy programu s± raportowane z wykorzystaniem 
.B syslogd (8).

.SH OPCJE
.TP
.BI --help
Wy¶wietla pomoc i na tym koñczy wykonanie programu.
  
.TP
.BI --version
Wy¶wietla pomoc i na tym koñczy wykonanie programu.
 
.TP
.BI --debug
Uruchamia w trybie usuwania b³êdów (domy¶lnie wy³±czone).
  
.TP
.BI --conf " plik"
Odczytuje konfiguracjê z
.I pliku
,którego ka¿da linia odpowiada jednej opcji
linii poleceñ pozbawionej przedrostka '--'.  Opcje podane w linii poleceñ
nadpisuj± opcje podane w pliku konfiguracyjnym.
 
.TP
.BI --pidfile " plik"
Nazwa
.I pliku
z identyfikatorem procesu (domy¶lnie ./sgsnemu.pid)
  
.TP
.BI --statedir " ¶cie¿ka"
.I ¦cie¿ka
do katalogu z trwa³ymi (nie ulotnymi) danymi (domy¶lnie ./)

.TP
.BI --dns " host"
Serwer DNS wykorzystywany do zapytañ APN.
Je¶li parametr zosta³ pominiêty, wykorzystywana jest domy¶lna, systemowa konfiguracja DNS.

.TP
.BI --listen " host"
Lokalny adres IP, który zostanie u¿yty do nas³uchu przez interfejs Gn/Gp.
Ta opcja musi zostaæ podana.
Z przyczyn bezpieczeñstwa nie mo¿e byæ wykorzystany INADDR_ANY.

.TP
.BI --remote " host"
.I Host
z wêz³em GGSN wykorzystywanym do po³±czeñ.  Je¶li DNS jest prawid³owo skonfigurowany
to powinno byæ mo¿liwe podanie nazwy punktu dostêpowego (APN) jako nazwy zdalnego hosta.

.TP
.BI --contexts " liczba"
Liczba ustanawianych kontekstów (domy¶lnie = 1).  W przypadku wielu kontekstów
pierwszy kontekst jest ustanawiany z wykorzystaniem imsi + 0 i msidn + 0.
Drugi kontekst jest ustanawiany z wykorzystaniem imsi + 1 i msidn +1.
Trzeci ...

.TP
.BI --timelimit " sekundy"
Koñczy wykonanie
.b sgsnemu
po up³ywie podanej liczy \fIsekund\fP.
W przypadku wykorzystywania opcji ping mo¿na zakoñczyæ
.B sgsnemu
po wy³aniu
.B --pingcount
pakietów.  

.TP
.BI --gtpversion " wersja"
.I wersja
protoko³u GTP wykorzystywana przy ustanawianiu kontekstów (domy¶lnie = 1).
Je¶li nie jest mo¿liwe ustanowienie kontekstu GTPw1
.B sgsnemu
powtórzy ¿±danie wykorzystuj±c GTPw0.
  
.TP
.BI --apn " apn"
.I apn
wykorzystywany przy ³±czeniu siê z wêz³em GGSN (domy¶lnie = internet).
APN jest akronimem angielskich s³ów Access Point Name.

.TP
.BI --selmode " tryb"
Tryb wyboru wykorzystywany w komunikacji z wêz³em GGSN (domy¶lnie = 0x01).
Jako tryby wyboru mog± byæ wykorzystane nastêpuj±ce kody:
0: MS lub sieæ dostarczana przez APN, subskrypcja zweryfikowana,
1: MS dostarczany przez APN, subskrypcja nie zweryfikowana,
2: sieæ dostarczana przez APN, subskrypcja nie zweryfikowana.

.TP
.BI --imsi " imsi"
.I imsi
wykorzystywane w komunikacji z wêz³em GGSN (domy¶lnie = 240010123456789).
IMSI jest akronimem angielskich s³ów International Mobile Subscriber Identity.
IMSI musi sk³adaæ siê z dok³adnie 15 cyfr.  Porównaj z opcj±
.I contexts
by zobaczyæ wykorzystanie 
.I imsi
w przypadku wielu kontekstów.

.TP
.BI --nsapi " nsapi"
.I nsapi
wykorzystywane w komunikacji z wêz³em GGSN (domy¶lnie = 0).
Warto¶æ musi byæ pomiêdzy 0, a 15.

.TP
.BI --msisdn " msisdn"
.I msisdn
wykorzystywane w komunikacji z wêz³em GGSN (domy¶lnie = 46702123456).
MSISDN jest akronimem angielskich s³ów International Mobile Integrated Services Digital Network.
W istocie jest numerem telefonu zapisanym w miêdzynarodowym formacie bez wiod±cych 00 lub 011.
Porównaj z opcj±
.I contexts
by zobaczyæ wykorzystanie 
.I msisdn
w przypadku wielu kontekstów.

.TP
.BI --qos " qos"
.I qos
wykorzystywany w komunikacji z wêz³em GGSN (domy¶lnie = 0x0b921f).
QoS jest akronimem angielskich s³ów Quality of Service.
Format tego parametru zosta³ okre¶lony na podstawie specyfikacji 3GPP 09.60.

.TP
.BI --charging " op³ata"
Charakterystyka rozliczania wykorzystywana w komunikacji z wêz³em GGSN
(domy¶lnie = 0x0800).  0x0800 = normalna, 0x0400 = przedp³ata,
0x0200 = p³aska rata, 0x0100 = rozliczanie dynamiczne.
Format pola zosta³ opisany w specyfikacji 3GPP 32.015.

.TP
.BI --uid " uid"
Identyfikator u¿ytkownika wysy³any do GGSN jako opcja konfiguracyjna protoko³u.

.TP
.BI --pwd " has³o"
Identyfikator wysy³ane do GGSN jako opcja konfiguracyjna protoko³u.

.TP
.BI --createif
Tworzy lokalny interfejs tun, wykorzystywany dla
przesy³ania pakietów do i z interfejsu Gn/Gp.
Nale¿y zaznaczyæ, ¿e interfejs Gn/Gp zazwyczaj jest kierowany
do Internetu przez GGSN.  Tylko jeden interfejs mo¿e byæ utworzony, chocia¿
wiele kontekstów mo¿e zostaæ ustanowionych.
Interfejs mo¿e byæ podany dla ka¿dego kontekstu jako adres IP, lub mo¿e byæ
okre¶lony za pomoc± opcji
.I net.

.TP
.BI --net " sieæ"
Adres sieci lokalnego interfejsu.
Opcja
.I net
jest poprawna tylko wtedy, gdy zosta³a wykorzystana opcja
.I createif.
Warto¶æ parametru
.I net
jest podawana w formacie cidr (sieæ/maska).  Je¶li opcja
.I net
zostanie pominiêta, adres IP jest rezerwowany dla ka¿dego ustanawianego kontekstu.

.TP
.BI --defaultroute
Definiuje domy¶lne trasowanie przez lokalny interfejs tun.

.TP
.BI --ipup " skrypt"
Skrypt wykonywany po aktywacji interfejsu Gi w sieci tun.
Skrypt jest uruchamiany z nastêpuj±cymi parametrami <nazwa urz±dzenia> <adres ip>.
  
.TP
.BI --ipdown " skrypt"
Skrypt wykonywany po wy³±czeniu interfejsu Gi w sieci tun.
Skrypt jest uruchamiany z nastêpuj±cymi parametrami <nazwa urz±dzenia> <adres ip>.
  
.TP
.BI --pinghost " host"
Powoduje wysy³anie pakietów ICMP do urz±dzenia
.I host
poprzez interfejs Gn/Gp.  Statystyki po³±czeñ s± raportowane w formie
bardzo zbli¿onej do wyj¶cia oryginalnego programu ping.  Mo¿esz wykorzystaæ
to udogodnienie do testowania wydajno¶ci GGSN.

.TP
.BI --pingrate " liczba"
Ilo¶æ ¿±dañ ICMP generowanych w przeci±gu sekundy (domy¶lnie = 1).

.TP
.BI --pingsize " liczba"
Rozmiar generowanych ¿±dañ ICMP wyra¿ony w oktetach (domy¶lnie = 56).


.TP
.BI --pingcount " liczba"
Oczekiwana ilo¶æ wygenerowanych ¿±dañ ICMP (domy¶lnie  = 0).
Warto¶æ 0 (zero) oznacza wielko¶æ nieograniczon±.

.TP
.BI --pingquiet
Wy³±cza wypisywanie informacji o otrzymanych pakietach (domy¶lnie pakiety s± wypisywane).
Jest to ca³kiem przydatne dla du¿ych ilo¶ci pakietów ICMP generowanych w przeci±gu sekundy
(porównaj z opcj± pingrate).

.SH PLIKI
.I sgsnemu.conf
.RS
Plik konfiguracyjny dla
.B sgsnemu.
.RE
.I .sgsnemu.pid
.RS
Plik zawieraj±cy identyfikator procesu.
.RE
.I ./
.RS
Katalog przechowuj±cy trwa³e (nie ulotne) dane.
.RE

.SH B£ÊDY
Zg³aszaj b³êdy na listê ¶ledzenia b³êdów OpenGGSN
.I http://sourceforge.net/projects/sgsnemu/


.SH "ZOBACZ TAK¯E"
.BR ggsn (8), 
.BR syslog (8)

.SH UWAGI
.LP

Oprócz d³ugich, udokumentowanych w tym podrêczniku, opcji
.B sgsnemu
wspiera równie¿ pewn± liczb± krótkich opcji o tej samej funkcjonalno¶ci.
Wywo³aj 
.B sgsnemu --help
by uzyskaæ pe³n± listê dostêpnych opcji.

Sterownik TUN/TAP jest wymagany dla poprawnego dzia³ania
.B sgsnemu. 
Dla j±der linuksa pó¼niejszych ni¿ 2.4.7 sterownik TUN/TAP jest zawarty w j±drze,
chocia¿ w typowej sytuacji musi byæ ³adowany oddzielnie za pomoc±
.B modprobe tun.
Aby ³adowaæ automatycznie nale¿y do pliku
.B /etc/modules.conf.
dodaæ liniê  
.B alias char-major-10-200 tun
Aby uzyskaæ informacje o innych platformach zobacz stronê
.I http://vtun.sourceforge.net/tun/
opisuj±c± jak zainstalowaæ i skonfigurowaæ sterownik tun.

.B ggsn 
wykorzystuje protokó³ tunelowania GPRS (GTP) wyspecyfikowany przez 
Third Generation Partnership Project (3GPP). Specyfikacje protoko³ów 3GPP
mog± byæ znalezione na
.I http://www.3gpp.org

.SH COPYRIGHT

Copyright (C) 2002, 2003, 2004 by Mondru AB.

Zawarto¶æ tego pliku mo¿e byæ wykorzystywana stosownie do terminów
Ogólnej, Publicznej Licencji (GPL) GNU w wersji 2 dostarczonej wraz
z niniejsz± uwag± o prawach autorskich zawart± we wszystkich kopiach
i istotnych fragmentach oprogramowania.

.SH AUTORZY
Jens Jakobsen <jj@openggsn.org>

.SH T£UMACZENIE
Polish translation copyright (C) 2004 Marek ¯akowicz <mazaczek@users.sourceforge.net>

T³umaczenie jest chronione prawami autorskimi.
Dozwolone jest korzystanie, rozprowadzanie i modyfikacja na zasadach licencji GNU GPL 2.
