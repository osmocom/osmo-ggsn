
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

.TH ggsn 8 "Lipiec 2003"
.SH NAZWA
ggsn \- Wêze³ Wspieraj±cy Bramy GPRS (ang. Gateway GPRS Support Node).
.SH U¯YTKOWANIE
.B ggsn
\-\-help
  
.B ggsn
  \-\-version

.B ggsn
[
.BI \-\-fg
] [
.BI \-\-debug
] [
.BI \-\-conf " plik"
] [
.BI \-\-pidfile " plik"
] [
.BI \-\-statedir " plik" 
] [ 
.BI \-\-listen " host" 
] [
.BI \-\-net " sieæ" 
] [
.BI \-\-ipup " skrypt" 
] [
.BI \-\-ipdown " skrypt" 
] [
.BI \-\-dynip " sieæ" 
] [
.BI \-\-statip " sieæ" 
] [
.BI \-\-pcodns1 " host" 
] [
.BI \-\-pcodns2 " host" 
] [
.BI \-\-timelimit " sekundy" 
]

.SH OPIS
.B ggsn
jest czê¶ci± projektu 
.B OpenGGSN
i implementuje funkcjonalno¶æ wêz³a wspieraj±cego bramy GPRS.
Wêz³y GGSN s± wykorzystywane przez operatorów sieci komórkowych jako interfejsy
pomiêdzy Internetem i reszt± infrastruktury sieci komórkowej.
  
Funkcjonalno¶æ i protoko³y GPRS zosta³y ustandaryzowane w ramach projektu
Third Generation Partnership Project (3GPP).  Stosownie do specyfikacji 3GPP,
GGSN posiada dwa interfejsy: interfejs Gn/Gp oraz interfejs Gi.
 
Interfejs Gn/Gp mo¿e byæ postrzegany jako ³±cze podrzêdne wêz³a GGSN.
Jest on wykorzystywany do komunikacji z Wêz³em Dostarczaj±cym Us³ug GPRS
(SGSN), który z kolei jest interfejsem do radiowej sieci dostêpowej.
Interfejs Gn/Gp wykorzystuje protokó³ tunelowania GPRS (GTP).  Pakiety danych
u¿ytkownika (zazwyczaj pakiety IP) s± tunelowane za po¶rednictwem protoko³u GTP,
który z kolei wykorzystuje protokó³ UDP nad IP.
  
Drugi z interfejsów mo¿e byæ postrzegany jako ³±cze nadrzêdne,
prowadz±ce z wêz³a GGSN do zewnêtrznej sieci danych.
Gi jest najczê¶ciej interfejsem do Internetu.
 
.B ggsn
wykorzystuje
.B sterownik TUN/TAP
jako interfejs Gi.  Interfejs w sieci tun jest uruchamiany podczas startu
.B ggsn.
 
.B ggsn
odbiera po³±czenia nadchodz±ce od urz±dzeñ ruchomych za po¶rednictwem
sieci radiowej oraz SGSN.  Gdy nadchodzi ¿±danie po³±czenia, ggsn rezerwuje
dla urz±dzenia ruchomego dynamiczny adres IP i pozwala urz±dzeniu ruchomemu
korzystaæ z interfejsu Gi.  Po³±czenia mog± byæ zamykane zarówno przez
stacje ruchome, jak i SGSN.  B³êdy wystêpuj±ce podczas pracy programu
s± raportowane z wykorzystaniem 
.B syslogd (8).
  
W typowej sytuacji
.B ggsn
jest uruchamiany na komputerze z dwoma kartami Ethernet - jedn±
przeznaczon± dla interfejsu Gn/Gp i jedn± dla interfejsu Gi.
Polityki trasowania i regu³y ¶ciany ogniowej powinny byæ wykorzystane
w celu rozdzielenia ruchu Gi od ruchu Gn/Gp.
  
.SH OPCJE
.TP
.BI --help
Wy¶wietla pomoc i na tym koñczy wykonanie programu.
  
.TP
.BI --version
Wy¶wietla pomoc i na tym koñczy wykonanie programu.
 
.TP
.BI --fg
Uruchamia na pierwszym planie (domy¶lnie wy³±czone).
  
.TP
.BI --debug
Uruchamia w trybie usuwania b³êdów (domy¶lnie wy³±czone).
  
.TP
.BI --conf " plik"
Odczytuje konfiguracjê z
.I pliku
(domy¶lnie /etc/ggsn.conf), którego ka¿da linia odpowiada jednej opcji
linii poleceñ pozbawionej przedrostka '--'.  Opcje podane w linii poleceñ
nadpisuj± opcje podane w pliku konfiguracyjnym.
 
.TP
.BI --pidfile " plik"
Nazwa
.I pliku
z identyfikatorem procesu (domy¶lnie /var/run/ggsn.pid)
  
.TP
.BI --statedir " ¶cie¿ka"
.I ¦cie¿ka
do katalogu z trwa³ymi (nie ulotnymi) danymi (domy¶lnie /var/lib/ggsn/)
 
.TP
.BI --listen " host"
Lokalny adres IP, który zostanie u¿yty do nas³uchu przez interfejs Gn/Gp.
Ta opcja musi zostaæ podana.
Z przyczyn bezpieczeñstwa nie mo¿e byæ wykorzystany INADDR_ANY.

.TP
.BI --net " sieæ"
Adres sieci interfejsu Gi (domy¶lnie 192.168.0.0/24).
Adres sieci jest ustawiany podczas inicjalizacji, gdy
.B ggsn
uruchamia urz±dzenie tun dla interfejsu Gi.
 
.TP
.BI --ipup " skrypt"
Skrypt wykonywany po aktywacji interfejsu Gi w sieci tun.
Skrypt jest uruchamiany z nastêpuj±cymi parametrami <nazwa urz±dzenia> <adres ip>.
  
.TP
.BI --ipdown " skrypt"
Skrypt wykonywany po wy³±czeniu interfejsu Gi w sieci tun.
Skrypt jest uruchamiany z nastêpuj±cymi parametrami <nazwa urz±dzenia> <adres ip>.
  
.TP
.BI --dynip " sieæ"
Pula dynamicznych adresów sieci IP.  Okre¶la pulê dynamicznych adresów IP.
Je¶li ta opcja zostanie pominiêta, ggsn wykorzystuje do dynamicznej rezerwacji
adresów IP, adres sieci okre¶lony przez opcjê
.BI --net.
  
.TP
.BI --pcodns1 " host"
Serwer PCO DNS 1 (domy¶lnie 0.0.0.0). PCO jest akronimem 
Protocol Configuration Options, co t³umaczy siê jako Protokó³ Opcji
Konfiguracyjnych i jest czê¶ci± specyfikacji prtoko³ów GPRS.  Jest
wykorzystywany do informowania stacji ruchomej o adresie serwera DNS
stosowanego do rozwi±zywania nazw hostów.
  
.TP
.BI --pcodns2 " host"
Serwer PCO DNS 2 (domy¶lnie 0.0.0.0). PCO jest akronimem 
Protocol Configuration Options, co t³umaczy siê jako Protokó³ Opcji
Konfiguracyjnych i jest czê¶ci± specyfikacji prtoko³ów GPRS.  Jest
wykorzystywany do informowania stacji ruchomej o adresie serwera DNS
stosowanego do rozwi±zywania nazw hostów.
  
.TP
.BI --timelimit " sekundy"
Koñczy wykonanie
.b ggsn
po up³ywie podanej liczy \fIsekund\fP.
Opcja wykorzystywana w celu usuwania b³êdów.
  

.SH PLIKI
.I /etc/ggsn.conf
.RS
Plik konfiguracyjny dla
.B ggsn.
.RE
.I /var/run/ggsn.pid
.RS
Plik zawieraj±cy identyfikator procesu.
.RE
.I /var/lib/ggsn
.RS
Katalog przechowuj±cy trwa³e (nie ulotne) dane.
.RE

.SH B£ÊDY
Zg³aszaj b³êdy na listê ¶ledzenia b³êdów OpenGGSN
.I http://sourceforge.net/projects/ggsn/

.B ggsn
ma bardzo ograniczone wsparcie dla zarz±dzania.
Obecnie zarówno SNMP jak i mechanizmy rozliczania s± pominiête.
  
.SH "ZOBACZ TAK¯E"
.BR sgsnemu (8), 
.BR syslogd (8)
 
.SH UWAGI
.LP
  
Oprócz d³ugich, udokumentowanych w tym podrêczniku, opcji
.B ggsn
wspiera równie¿ pewn± liczb± krótkich opcji o tej samej funkcjonalno¶ci.
Wywo³aj 
.B ggsn --help
by uzyskaæ pe³n± listê dostêpnych opcji.

Sterownik TUN/TAP jest wymagany dla poprawnego dzia³ania
.B ggsn. 
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

Copyright (C) 2002, 2003 by Mondru AB.

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
