# chkweb
Python skripta za proveru promena na web stranicama.
Testirano na Linux sistemu.

Prilozen i primer bash skripte koja bi pokretala ovu skriptu.

Da bi skripta funkcionisala na vasem sistemu potrebno je da u 'chkweb.py' fajlu promenite promenljivu 'path' na putanju gde se nalazi skripta 'chkweb.py' i njeni propratni .txt fajlovi. Zgodno bi bilo da sve stoji u zasebnom folderu, recimo imena 'chkweb_data'.

Uputstvo za koriscenje:
Ispravna upotreba:      chkweb <opcije> <link/nadimak> <nadimak>
Opcije:
        bez opcije              ispisuje ovaj help
        help                    ispisuje ovaj help
        -l                      ispisuje logove
        -L                      ispisuje listu svih sajtova sa njihovim nadimcima
        -p                      ispisuje putanju gde se traze fajlovi za skriptu
        -a <link> <nadimak>     dodaje novi sajt sa datim nadimkom u listu
        -a <nadimak>            dodaje sajt sa datim nadimkom u listu, samo ako je zakomentarisan
        -r <nadimak>            uklanja sajt sa datim nadimkom iz liste
        -c <nadimak>            stavlja sajt sa datim nadimkom u komentar
        -u                      radi update i proverava za promene na sajtovima

Ocekuje se da prosledjeni link bude oblika http://www.google.com/, http://elektronika.etf.bg.ac.rs/,...
