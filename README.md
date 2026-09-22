# Clanker

Mrežni alat za CTF natjecanja koja zabranjuju korištenje AI alata, ali
dopuštaju normalan pristup internetu. Igrači se spajaju na hotspot koji
kontrolira organizator; DNS blocker propušta sav promet osim upita prema
poznatim AI servisima (ChatGPT, Claude, Gemini, Copilot, itd.). Uz
terminal dashboard postoji i web dashboard (Astro) s pregledom uređaja
uživo i gumbom za odspajanje.

## Status

Rana faza / MVP za testiranje. Trenutno gotovo:

- DNS blocker sa sinkhole listom AI domena i ključnih riječi, presreće
  promet preko WinDivert-a jer Windows ICS/Mobile Hotspot već drži port
  53 (`guard/dns_blocker.py`) - vidi napomenu ispod
- Terminal dashboard uživo: uređaji + zadnji DNS upiti (`guard/dashboard.py`)
- **Web dashboard** (Astro, `web/`) na `http://127.0.0.1:8420` - prigušen,
  formalan stil (blijedo žuta pozadina, smeđe/zlatne boje, blaga
  transparentnost i suptilno pulsiranje pozadine, bez neon-a), sidebar
  navigacija, uređivo uživo:
  - **Odabir uređaja u navigaciji** - klikni uređaj u sidebaru (ili IP u
    tablici) za detaljan prikaz: graf prometa, filtrirani DNS upiti
    samo za taj uređaj, gumb za odspajanje
  - **Log po uređaju, ne jedan veliki firehose** - na Pregledu, svaki
    red uređaja ima strelicu koja otvara njegov log u fiksnom,
    scrollable panelu. Scroll pozicija se ne resetira na svako
    osvježavanje (1.5s) - samo klik na "UŽIVO" te vrati na vrh
  - **Grafovi na Pregledu** - bar chart "blokirano po uređaju" i area
    chart "ukupni promet" preko svih uređaja, namjerno kompaktni
  - gumb za odspajanje uređaja (Windows Firewall blokada po IP-u; vidi
    ograničenje ispod)
  - **Banuj domenu izravno iz loga** - hoveraj na status bilo kojeg
    upita da se pojavi gumb BLOCK; nema više posebnog "Live Blocklist"
    panela s poljem za unos, banuj točno ono što vidiš u logu
    (backend i dalje `guard/blocklist.py` `add_live_domain`, perzistira
    u `config/live_blocklist.json`)
  - **Uređaji sortirani po ozbiljnosti** - odspojeni/sumnjivi/s
    blokiranim upitima isplivaju na vrh liste (i u sidebaru i u
    tablici), bitno kad je spojeno puno uređaja
  - **Promet po uređaju** - sparkline/area graf zadnjih ~60s prometa
    (`guard/traffic_meter.py`, WinDivert byte-counter) i heuristička
    "SUMNJIVO" oznaka kad je promet uređaja daleko iznad ostalih - vidi
    ograničenje ispod, ovo NIJE dokaz AI korištenja
  - **Severity bojanje** (tri razine): tamnoplavo + "!!" za pokušaj
    zaobilaženja DNS-a preko poznatog DoH/DoT resolvera (`doh_providers`
    u blocklist.yaml - vidi ispod), opečeno crveno + "!" za potvrđenu AI
    domenu (točan match u kuriranoj/live listi), narančasto za
    "sumnjivo" (samo keyword match, npr. spominje "grok" ali nije
    x.ai/grok.com)
- ARP-based popis spojenih uređaja (`guard/devices.py`)
- Legacy Windows hotspot helperi (`guard/hotspot.py`)
- **Eksperimentalno**, još nije spojeno u dashboard: SNI-based deep
  packet monitor preko WinDivert-a, hvata pokušaje i kad klijent
  zaobiđe DNS (`guard/traffic_monitor.py`) - ne treba brkati s
  `traffic_meter.py` (bandwidth brojanje, već integriran)

### DoH zaobilaženje - detekcija

Klijent koji ignorira DHCP DNS i ručno gađa poznati DNS-over-HTTPS/DoT
resolver (cloudflare-dns.com, dns.google, dns.quad9.net...) pokušava
zaobići DNS blocker u cjelini - to je mnogo jači signal namjere nego
običan keyword hit, jer normalan korisnik nema razloga ručno mijenjati
DNS na natjecateljskoj mreži. `Blocklist` sad prepoznaje i blokira ove
domene kao zasebnu "evasion" kategoriju (`config/blocklist.yaml`
`doh_providers:`), prikazanu posebnom magenta bojom u dashboardu.
Napomena: ovo ne hvata DoH koji ide direktno na IP bez DNS upita za sam
resolver, niti enkriptirani SNI (ECH) - vidi ograničenja niže.

### Promet kao signal - ograničenje

Bandwidth sam po sebi je slab pokazatelj korištenja AI-a - video poziv,
Windows update ili veliki download izgledaju identično na žici kao
"puno prometa". "SUMNJIVO" oznaka uspoređuje uređaj s medijanom ostalih
aktivnih uređaja (leave-one-out, da jedan outlier ne iskrivi vlastitu
usporedbu) - tretiraj je kao "pogledaj pobliže", nikad kao dokaz.

### Odspajanje uređaja - ograničenje

Windows ne nudi API za pravu WiFi deautentifikaciju pojedinog Mobile
Hotspot klijenta. Gumb "ODSPOJI" u web dashboardu zato dodaje Windows
Firewall pravilo koje odreže sav promet do/od te IP adrese - uređaj
ostaje asociran na WiFi, ali nema internet. Dovoljno za CTF svrhu, ali
ako uređaj dobije novu IP adresu (DHCP renew), pravilo treba ponovno
primijeniti na novu adresu.

### Zašto WinDivert umjesto običnog DNS servera

Prva verzija je pokušala vezati vlastiti DNS server na port 53. To ne
radi na Windowsu čim je Mobile Hotspot uključen: usluga **Internet
Connection Sharing (ICS)** koja pokreće hotspot već drži `0.0.0.0:53`
za svoj interni DNS proxy, pa `bind()` puca s
`WinError 10048 (Only one usage of each socket address...)`.
`DNSBlocker` umjesto toga presreće UDP/53 pakete na mrežnom sloju prije
nego stignu do ICS-a: blokirane upite tiho odbaci (klijent dobije
timeout), sve ostalo propusti netaknuto pa ih ICS riješi kao inače. Zbog
ovoga **nije potrebno ručno mijenjati DNS na hotspot adapteru** - ostavi
ga na automatski, blocker radi neovisno o tome koji DNS klijent misli
da koristi.

## Bitno ograničenje - pročitaj prije korištenja

Ovo je pomoćni alat za detekciju, **ne nepogrešiv sustav**. Ne hvata:

- **Mobilni podaci / tethering preko SIM-a** - taj promet nikad ne dotakne ovu mrežu
- **Lokalno pokrenut AI model bez interneta** (npr. Ollama) - nema mrežnog traga
- **VPN** koji tunelira sav promet - DNS proxy ne vidi stvarnu destinaciju
- **DNS-over-HTTPS** ako klijent ignorira DHCP DNS i koristi ugrađeni DoH
  (Firefox/Chrome to rade po defaultu) - ublažava se SNI slojem (faza 2),
  ali nije riješeno u ovom MVP-u

Ovo mora biti nadopunjeno pravilnikom natjecanja (potpisana izjava,
zabrana osobnih hotspotova, fizički nadzor). DNS upit prema AI domeni je
**signal za ručnu provjeru**, ne automatski dokaz za diskvalifikaciju
(netko može slučajno otvoriti anthropic.com iz znatiželje).

## Zahtjevi

- Python 3.10+
- Node.js 18+ (za Astro web dashboard)
- Windows 11 (testirano za Mobile Hotspot / legacy hosted network)
- `pip install -r requirements.txt`
- `cd web && npm install && npm run build` (jednom, i nakon svake izmjene `web/src`)

## Postavljanje hotspot-a

### Opcija A - legacy "hosted network" (skriptabilno)

Prvo provjeri podržava li tvoj WiFi adapter ovo (noviji Intel AX čipovi
često ne podržavaju):

```bash
python -m guard.main hotspot-check
```

Ako piše da je podržano:

```bash
python -m guard.main hotspot-start --ssid CTF-Test --password nekalozinka123
```

Zatim u **Postavke mreže i interneta > Promjena postavki adaptera** desni
klik na tvoj glavni internet adapter > Svojstva > kartica Dijeljenje >
uključi dijeljenje interneta za adapter "Microsoft Hosted Network Virtual
Adapter" (ovo je Internet Connection Sharing, ICS - Windows ga ne nudi
kroz `netsh`, mora se ručno u GUI-ju).

### Opcija B - Mobile Hotspot (GUI, radi na svim novijim laptopima)

1. Postavke > Mreža i internet > Mobile Hotspot > Uključi
2. To je sve - **ne diraj DNS postavke** adaptera, ostavi ih na
   automatske. `DNSBlocker` presreće promet neovisno o tome (vidi
   "Zašto WinDivert" gore).

## Pokretanje

Mora ići u **Administrator** PowerShell-u (WinDivert driver traži
povišene ovlasti):

```bash
python -m guard.main dns
```

Ovo pokrene DNS blocker, terminal dashboard (kao i prije), **i** web
dashboard na `http://127.0.0.1:8420` koji se sam otvori u browseru
(`--no-browser` to isključuje, `--no-dashboard` iskljucuje samo
terminal prikaz ako želiš samo web).

Spoji telefon na hotspot, otvori bilo koju normalnu stranicu (treba
raditi), pa probaj `claude.ai` ili `chat.openai.com` (treba se zaglaviti
/ timeout, nema instant NXDOMAIN u ovoj verziji) - oba pokušaja trebaju
se pojaviti u oba dashboarda s tvog telefona (MAC adresa). Gumb
"ODSPOJI" u web dashboardu odreže internet toj IP adresi.

Provjera spojenih uređaja bez dashboarda:

```bash
python -m guard.main devices
```

## Održavanje blocklist-e

`config/blocklist.yaml` - dodaj domenu ili ključnu riječ i pokreni
ponovno (nema potrebe za izmjenom koda). Keyword match hvata i nove/
nepoznate poddomene, ali može false-positive-ati (npr. "llama" je i ime
životinje) - tretiraj alert kao naznaku, ne kao presudu.

## Sljedeći koraci (roadmap)

1. Spojiti `traffic_monitor.py` (SNI) u dashboarde kao drugi izvor
   signala, neovisan o DNS-u klijenta - i za IP-only DoH koji ne prolazi
   kroz normalan DNS upit
2. Live-update web dashboarda preko WebSocket/SSE umjesto pollinga
3. Za produkciju na natjecanju: OpenWrt ruter kao AP + ovaj laptop kao
   monitoring/kontrolna stanica (robusnije od laptopa kao jedinog AP-a)
