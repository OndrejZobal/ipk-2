# Dokumentace k 2. projektu do IPK 2023

Ondřej Zobal (xzobal01)

* * *

## Teorie

### TCP
    
 TCP je spolehlivý protokol transportní vrstvy, který pro rozlišení  cílové
aplikace používá šestnáctibitová čísla zvaná porty. Když skenujeme porty,
snažíme se zjistit, zda na konkrétní portu poslouchá nějaká  aplikace (a
případně jaká), leží ladem, nebo zda je komunikace tohoto  portu filtrována
firewallem.

 Než může aplikace začít komunikovat pomocí protokolu TCP musí nejprv  navázat
spojení. Prvně pošle žadatel paket SYN, kterým žádá o navázání  nového spojení,
adresát pak může s připojením souhlasit a poslat paket SYN ACK, nebo odmítnout a
poslat paket RST. Pokud adresát spjení přijal žadatel obdržel paket SYN ACK,
pošle vzdálenému počítači paket ACK, čímž se TCP spojení oficiálně považuje za
otevřené.

 Pro účely skenování můžeme tedy cílovému zařízení poslat segment SYN a  čekat,
jak odpoví. Pokud nazpátek obdržíme segment SYN ACK, znamená to, že je tento
port aktivně používán nějakou aplikací a je tudíž otevřený.  Pokud obdržíme
paket RST jako odpověď, znamená to, že tento port  nepřijímá žádná spojení a je
tedy zavřený. Pokud neobdržíme žádnou  odpověď, znamená to, že naši žádost
zablokoval paketový filtr.


### UDP

 UDP je téže protokol transportní vrstvy, avšak na rozdíl od TCP je  bezstavový
a neručí za bezpečné doručení zprávy. Podobně jako TCP i UDP používá
šestnáctibitové identifikátory pro rozlišení aplikací. Při  komunikaci přes UDP
posíláme data rovnou, bez nutnosti navazovat  spojení. Kvůli tomu nemůže
spolehlivě zjistit, zda je daný port  otevřený nebo filtrovaný. Jediným
indikátorem pro nás může být, že při  kontaktu se zavřeným portem některé
zařízení posílají chybové hlášení  protokolu ICMP, což neznačuje že daný port je


## Popis implementace

### Reprezentace portů v paměti

 Aby se porty na výstupu objevily ve stejném pořadí jako na vstupu,  použil jsem
TRP `PortMap`, která jako klíč používá číselnou hodnotu portu a jako data jeho
stav (tj. otevřený, zavřený, filtrovaný.) V kombinaci s  vektorem `PortEnumer`,
kde index reprezentuje pořadí portu na vstupu a  užitečnou hodnotou je pár
tvořený typem protokolu a číslem portu. Ve  vektoru pro výčet portů se tedy
objevují porty protokolu TCP i UDP,  zatímco TRP používám dvě, aby měl každý
protokol vlastní.


### Skenování

 Skenování probíhá souběžně ve třech vláknech. Hlavní vlákno programu  rozesílá
skenovací pakety a dvě vedlejší vlákna naslouchají příchozím  zprávám protokolů
TCP a ICMP. Obě přijímací vlákna zkoumají surové pakety svých protokolů  a
informace o portech zanáší do TRP.  Aby nedošlo k přehlcení koncového  zařízení,
mezi odesláním každého skenovacího paketu program počká 20  mikrosekund. 

 K výrobě i čtení paketů používám vestavěné struktury `iphdr`, `tcphdr`,
`udphdr` a `icmphdr`. Paměť obsahující paket přetypuji na příslušnou  strukturu
a s daty pracuji jako s jakoukoliv jinou strukturou jazyka C.  Jelikož používám
syrové sokety, musím kontrolovat, že příchozí segmenty  byly skutečně adresovány
mému skeneru.

 V moment kdy hlavní vlákno dokončí rozesílání všech paketů, pošle  signál, (v
podobě změny hodnoty atomické proměnné,) dvěma přijímacím  vláknům, která si od
toho okamžiku začnou odpočítávat časový interval specifikovaný na vstupu. Po
uplynutí časomíry obě vedlejší vlákna skončí.

### Tisk

 Tištění výstupu provádím postupným procházením portů ve vektoru portů a
vyhledáváním jejich stavu v TRP.


## Testování

 Program jsem testoval na svém serveru se zapnutým i vypnutým firewallem. Při
testování libovolného počtu TCP portů, výsledky přesně odpovídaly konfiguraci
zařízení. Při testování UDP portů, pouze prvních 6 testovaných zavřených portů
vrátilo chybový ICMP segment, tento limit je dán nastavením cílového zažízení

* * *


## Použité zdroje

> RFC 1071 - Computin the internet Checksum
> https://www.rfc-editor.org/rfc/rfc1071

> RFC 9293 - Transmission Control Protocol (TCP)
> https://www.rfc-editor.org/rfc/rfc9293

> RFC 768 - User Datagram Protocol
> https://www.rfc-editor.org/rfc/rfc768.html

> C++ reference 
> https://en.cppreference.com/w/

> NMAP - TCP SYN (Stealth) Scan (-sS)
> https://nmap.org/book/synscan.html

> OpenSource For U - A guide to using raw sockets
> https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/

> Manuálové stránky jazyka C
