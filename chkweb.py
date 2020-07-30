#!/usr/bin/python3.8

# direktorijum gde se nalaze svi potrebni fajlovi
path = '/home/ris/Documents/bashscripts/chkweb_data/'

# format podataka:
# 
# za websites.txt:
# <link> <nadimak>
# ako linija zapocinje sa # smatrati da je zakomentarisana i da je nema
#
# za hash.txt
# <vreme>
# <nadimak> <hash>
# ...
#
# za log.txt
# <vreme>	dodat/sklonjen/exception <link> <nadimak>
# ...
#
# argumenti:
# '-l' ispisuje logove
# '-p' ispisuje putanju gde se nalaze fajlovi za skriptu
# '-L' ispisuje listu svih sajtova sa nadimcima
# '-a <link> <nadimak>' dodaje novi sajt sa nadimkom
# '-a <nadimak>' dodaje sajt sa datim nadimkom ako je takav zakomentarisan
# '-r <nadimak>' sklanja sajt sa datim nadimkom
# '-c <nadimak>' sajt sa datim nadimkom stavlja u komentar
# '-u' radi update i proverava za promene na sajtovima
# 'help' ispisuje ovo uputstvo
# bez argumenta isto ispisuje ovo uputstvo

# sluzi za hashovanje
import hashlib

# sluzi za otvaranje browser-a
import webbrowser

# sluzi za slanje http zahteva
import requests as req

# sluzi za dobijanje trenutnog vremena
from datetime import datetime

now = datetime.now()
#trenutno vreme
time = now.strftime("%d-%m-%Y %H:%M:%S")

# za argumente
import sys

# za proveru da li je fajl prazan
import os

# treba napraviti odvojene funkcije za:
	# proveru da li je prosledjeni fajl prazan ili ima samo newline karaktere (vraca bool) (bitno ako nisu inicijalizovani fajlovi)
	# pronalazenje website preko linka (vraca [link, nadimak])
	# pronalazenje website preko nadimka (vraca [link, nadimak])
	# dodavanje novog website
	# uklanjanje website preko nadimka
# kod za njih se moze naci dole u skripti, samo ih treba lepo formatirati i prekucati sve kako treba ponovo
# prosto da bi urednije izgledao kod i mozda malo bolje radilo (barem sigurno sto se tice inicijalizacije fajlova)

# pomocna funkcija za ispis help-a
def print_help():
	print('Ispravna upotreba:'+'\t'+'chkweb <opcije> <link/nadimak> <nadimak>')
	print('Opcije:')
	print('\t'+'bez opcije'+'\t\t'+'ispisuje ovaj help')
	print('\t'+'help'+'\t\t\t'+'ispisuje ovaj help')
	print('\t'+'-l'+'\t\t\t'+'ispisuje logove')
	print('\t'+'-L'+'\t\t\t'+'ispisuje listu svih sajtova sa njihovim nadimcima')
	print('\t'+'-p'+'\t\t\t'+'ispisuje putanju gde se traze fajlovi za skriptu')
	print('\t'+'-a <link> <nadimak>'+'\t'+'dodaje novi sajt sa datim nadimkom u listu')
	print('\t'+'-a <nadimak>'+'\t\t'+'dodaje sajt sa datim nadimkom u listu, samo ako je zakomentarisan')
	print('\t'+'-r <nadimak>'+'\t\t'+'uklanja sajt sa datim nadimkom iz liste')
	print('\t'+'-c <nadimak>'+'\t\t'+'stavlja sajt sa datim nadimkom u komentar')
	print('\t'+'-u'+'\t\t\t'+'radi update i proverava za promene na sajtovima')
	print('\nOcekuje se da prosledjeni link bude oblika http://www.google.com/, http://elektronika.etf.bg.ac.rs/,...')
	
# sys.argv[0] je ime pozvane skripte, sve nadalje su argumenti

# 'help' ispisuje help, takodje i bez argumenata ispisuje help
if len(sys.argv) == 1:
	print_help()
elif sys.argv[1] == 'help':
	print_help()

# '-l' ispisuje logove
elif sys.argv[1] == '-l' and len(sys.argv) == 2:
	with open(path + 'log.txt') as f:
		print(f.read())

# '-p' ispisuje putanju gde se nalaze fajlovi za skriptu
elif sys.argv[1] == '-p' and len(sys.argv) == 2:
	print(path)

# '-L' ispisuje listu svih sajtova sa nadimcima
elif sys.argv[1] == '-L' and len(sys.argv) == 2:
	with open(path + 'websites.txt') as f:
		print(f.read())

# '-a <link> <nadimak>' dodaje novi sajt sa nadimkom
elif sys.argv[1] == '-a' and len(sys.argv) == 4:
	#0123456789
	#http://xxx
	if sys.argv[2][0:7] != 'http://':
		print('Neispravan link!')
		print('\nOcekuje se da prosledjeni link bude oblika http://www.google.com/, http://elektronika.etf.bg.ac.rs/,...')
	
	# trazenje da li vec postoji sajt
	found = False
	commented = False
	with open(path + 'websites.txt') as f:
		for line in f:
			# obratiti paznju da li je sajt zakomentarisan i ukloniti znak '#' iz 'line'
			if line[0] == '#':
				commented = True
				line = line[1:]
			line = line.strip().split()
			if line[0] == sys.argv[2]:
				found = True
				break
			commented = False
	
	# ako sajt vec postoji u listi i nije zakomentarisan, obavestava se korisnik i loguje se
	if found and not commented:
		print('Sajt ' + sys.argv[2] + ' vec postoji u listi')
		with open(path + 'log.txt', 'a') as f:
			f.write(time + '\tpokusaj dodavanja vec postojeceg sajta ' + sys.argv[2] + '\n')
	# ako sajt postoji u listi i zakomentarisan je, obavestava se korisnik i loguje se
	elif found and commented:
		print('Sajt ' + sys.argv[2] + ' vec postoji u listi i zakomentarisan je')
		with open(path + 'log.txt', 'a') as f:
			f.write(time + '\tpokusaj dodavanja zakomentarisanog sajta ' + sys.argv[2] + '\n')
	else:
		with open(path + 'websites.txt', 'a') as f:
			f.write(sys.argv[2] + '\t' + str(sys.argv[3]) + '\n')
		print('Dodat sajt ' + sys.argv[2] + ' sa nadimkom ' + sys.argv[3])
		# logovanje promene
		with open(path + 'log.txt', 'a') as f:
			f.write(time + '\tdodato iz komandne linije ' + sys.argv[2] + ' ' + sys.argv[3] + '\n')

# '-a <nadimak>' dodaje sajt sa datim nadimkom ako je takav zakomentarisan
elif sys.argv[1] == '-a' and len(sys.argv) == 3:
	lines = []
	found = False
	website = ''
	# trazenje date linije koja je zakomentarisana i provera da li je nadjen sajt sa datim nadimkom
	# usput pamcenje svih linija u 'lines'
	with open(path + 'websites.txt') as f:
		for line in f:
			lines.append(line)
			if line[0] == '#':
				temp = line[1:].strip().split()
				# ako je nadjen sajt, u lines se pamti linija koja nema '#' na pocetku
				if temp[1] == sys.argv[2]:
					found = True
					website = temp[0]
					lines[-1] = line[1:]	
	# ako je nadjen prepravlja se 'websites.txt'
	if found:
		with open(path + 'websites.txt', 'w') as f:
			for line in lines:
				f.write(line)
		print('Sajt ' + website + ' sa nadimkom ' + sys.argv[2] + ' je dodat u listu')
		# logovanje
		with open(path + 'log.txt', 'a') as f:
			f.write(time + '\todkomentarisan ' + website + ' ' + sys.argv[2] + '\n')
	else:
		print('Sajt sa nadimkom ' + sys.argv[2] + ' nije pronadjen u listi')			

# '-r <nadimak>' brise sajt sa datim nadimkom iz liste
elif sys.argv[1] == '-r' and len(sys.argv) == 3:
	lines = []
	found = False
	# trazenje datog nadimka
	# usput pamcenje svih linija u 'lines'
	with open(path + 'websites.txt') as f:
		for line in f:
			lines.append(line)
			line = line.strip().split()
			# ako je nadjen sajt, brise se ta linija iz lines
			if line[1] == sys.argv[2]:
				website = line[0]
				found = True
				line.pop()	
	# ako je nadjen prepravlja se 'websites.txt'
	if found:
		with open(path + 'websites.txt', 'w') as f:
			for line in lines:
				f.write(line)
		print('Sajt ' + website + ' sa nadimkom ' + sys.argv[2] + ' je izbrisan iz liste')
		# logovanje
		with open(path + 'log.txt', 'a') as f:
			f.write(time + '\tobrisan ' + website + ' ' + sys.argv[2] + '\n')
	else:
		print('Sajt sa nadimkom ' + sys.argv[2] + ' nije pronadjen u listi')			

# '-c <nadimak>' sajt sa datim nadimkom stavlja u komentar
elif sys.argv[1] == '-c' and len(sys.argv) == 3:
	lines = []
	found = False
	commented = False
	website = ''
	# trazenje datog nadimka
	# usput pamcenje svih linija u 'lines'
	with open(path + 'websites.txt') as f:
		for line in f:
			# dodavanje linije u 'lines', pa ako treba posle ce se dodati '#' na pocetak
			lines.append(line)
			# za temporary obradu
			temp = line.strip().split()
			# ako je nadjen sajt, u poslednjoj liniji 'lines' se dodaje '#' na pocetak
			if temp[1] == sys.argv[2]:
				found = True
				website = temp[0]
				# ako sajt nije zakomentarisan dodati '#'
				if lines[-1][0] != '#':
					lines[-1] = '#' + lines[-1]
				# inace zapamtiti da je bio zakomentarisan i prekinuti petlju
				else:
					commented = True
					break
					
	# ako je nadjen i nije zakomentarisan prepravlja se 'websites.txt'
	if found and not commented:
		with open(path + 'websites.txt', 'w') as f:
			for line in lines:
				f.write(line)
		print('Sajt ' + website + ' sa nadimkom ' + sys.argv[2] + ' je zakomentarisan')
		# logovanje
		with open(path + 'log.txt', 'a') as f:
			f.write(time + '\tzakomentarisan ' + website + ' ' + sys.argv[2] + '\n')
	# ako je nadjen i jeste zakomentarisan
	elif found and commented:
		print('Sajt ' + sys.argv[2] + ' vec postoji u listi i zakomentarisan je')
		# logovanje
		with open(path + 'log.txt', 'a') as f:
			f.write(time + '\tpokusaj zakomentarisanja zakomentarisanog sajta ' + sys.argv[2] + '\n')
	else:
		print('Sajt sa nadimkom ' + sys.argv[2] + ' nije pronadjen u listi')			

# '-u' radi update, proverava za promene na sajtovima
elif sys.argv[1] == '-u' and len(sys.argv) == 2:
	print("Trenutno vreme: "+time)
	# citanje liste stranica i njihovih nadimaka
	with open(path + 'websites.txt') as f:
		lines = []
		for line in f:
			if line[0] != '#':
				lines.append(line.strip().split())
		size = len(lines)
		websites = [ lines[i][0] for i in range(0, size)]
		new_nicknames = [ lines[i][1] for i in range(0, size)]

	# ako nema konekcije na neku od stranica ispisati za koju nema konekcije i ne izvrsavati dalje
	connection = True
	# html kodovi svih stranica
	for i in range(0,size):
		try:
			new_html = req.get(websites[i]).text
		except:
			connection = False
			print("Uhvacen Exception pri dobijanju html koda, proveriti konekciju sa sajtom ", websites[i])
			with open(path + 'log.txt', 'a') as f:
				f.write(time + '\tuhvacen Exception pri dobijanju html koda sajta ' + websites[i] + '\n')

	# ako nema konekcije na bilo koju od stranica, quit			
	if not connection:
		quit()
		
	# dobijanje html kodova
	new_html = [ req.get(websites[i]).text for i in range(0, size) ]

	#objekat za hashovanje
	sha_obj = hashlib.sha256()
	# hashovane vrednosti html kodova svih stranica
	new_hash = []
	for i in range(0, size):
		sha_obj.update(str.encode(new_html[i]))
		new_hash.append(sha_obj.digest())
	
	# ako 'hash.txt' nije prazan sve je okej
	if os.stat(path + 'hash.txt').st_size != 0:
		# citanje proslih hashova i nadimaka
		with open(path + 'hash.txt') as f:
			lines = [ line.strip().split() for line in f ]
			old_time = lines[0][0] + ' ' + lines[0][1]
			old_nicknames = [ lines[i][0] for i in range(1, len(lines))]
			old_hash = [ lines[i][1] for i in range(1, len(lines))]
			
		# provera da li je dodat sajt i ako jeste, upisati u log
		#ovde se cuvaju indeksi koji ce posle morati da budu preskoceni jer ne postoji prethodni hash sa kojim se poredi novi
		index2skip = []
		if len(new_hash) > len(old_hash):
			for i in range(0, len(new_nicknames)):
				found = False
				for j in range(0, len(old_nicknames)):
					if new_nicknames[i] == old_nicknames[j]:
						found = True
				# ako se ne nadje novi sajt u listi starih upisati u log da je dodat
				if not found:
					index2skip.append(i)
					with open(path + 'log.txt', 'a') as f:
						f.write(time + '\tprvi put pristupljeno ' + new_nicknames[i] + ' ' + websites[i] + '\n')
						
		# provera da li je sklonjen sajt i ako jeste, upisati u log
		if len(old_hash) > len(new_hash):
			for i in range(0, len(old_nicknames)):
				found = False
				for j in range(0, len(new_nicknames)):
					if old_nicknames[i] == new_nicknames[j]:
						found = True
				# ako se ne nadje stari sajt u listi novih upisati u log da je sklonjen
				if not found:
					with open(path + 'log.txt', 'a') as f:
						f.write(time + '\tprimeceno da je sklonjen ' + old_nicknames[i] + '\n')

		# poredjenje hasheva, gledanje koji su se promenili, upis u hashes.txt i promptovati da li otvoriti sajtove koji su bili izmenjeni

		# recnik sa starim nadimcima i njihovim hashevima
		old_dict = dict(zip(old_nicknames, old_hash))

		# ovde se cuvaju svi indexi sajtova koji su bili menjani
		changed = []
		# prolazak kroz sve nove nadimke i poredjenje hasheva
		for i in range(0, len(new_nicknames)):
			# obratiti paznju ako je dodat novi sajt da se ne trazi njegov stari hash
			if i not in index2skip:
				# ako se razlikuju hashevi zapamtiti koji su
				if str(new_hash[i]) != old_dict[new_nicknames[i]]:
					changed.append(i)

		# cuvanje novog hash.txt
		with open(path + 'hash.txt', 'w') as f:
			f.write(time + '\n')
			[f.write(new_nicknames[i] + ' ' + str(new_hash[i]) + '\n') for i in range(0, size)]
			
					
		# ako je neki sajt bio menjan
		if len(changed) > 0:
			print("Sajtovi koji su promenjeni od " + old_time + " su:")
			for i in changed:
				print(new_nicknames[i])
			# pitati korisnika da li zeli da ih otvori
			print("Zelite li da otvorite te sajtove? [y/N]")
			usr = input()
			if usr == 'y' or usr == 'Y':
				# prvi link se otvara u novom prozoru, naredni kao tabovi
				webbrowser.open(websites[changed[0]], new=1)
				for i in changed[1:]:
					webbrowser.open(websites[changed[i]], new = 2)
		# ako nije nijedan sajt bio menjan, obavestiti i o tome
		else:
			print("Nijedan od sajtova nije menjan od poslednje provere: " + old_time)
	# ako je 'hash.txt' prazan, treba ga kreirati
	else:
		print("Inicijalizacija fajla 'hash.txt'")
		with open(path + 'hash.txt', 'w') as f:
			f.write(time + '\n')
			[f.write(new_nicknames[i] + ' ' + str(new_hash[i]) + '\n') for i in range(0, size)]
			
else:
	print('Neispravna upotreba')
	print_help()
