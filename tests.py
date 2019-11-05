#!/usr/bin/python3
import itertools
from random import randrange, shuffle
import subprocess
import time

def recognize(lst, char): # rozpoznani typu vnitrniho seznamu v hlavnim seznamu
    i = 0
    for item in lst:
        if item[0] == char:
            item.pop(0) # odstran vlozeny typ
            return i
        i = i + 1 # zvys index

# SOUBORY S TESTOVYMI VYSTUPY
failed = open("tests/failed","w+")
generated = open("tests/generated","w+") # vsechny testy
passed = open("tests/passed", "w+")

# DATA PRO SPOUSTENI TESTU
data = [
        {'okh': ["kazi.fit.vutbr.cz","one.one.one.one"]},
        {'ok4': ["147.229.8.12","8.8.8.8","1.1.1.1"]},
        {'ok6': ["2606:4700:4700::1111","2606:4700:4700::1001"]},
        {'badh': ["1goog.",".cz..","-------",".2fefddf--ee"]},
        {'bad4': ["1.1.1","55.55.55..","257.34.34.34"]},
        {'bad6': ["2001:0db8:85a3:0000:0000:8a2e:0370:7334","2001:0db8:85a3:00GG:0000:8a2e:0370:7334","200:0db8:85a3:0000:0000:8a2e0370:7334"]}
        ]
shuffle(data) # promichej data adres a serveru

# VYGENERUJ GENEROVANI TESTU
list_a = list(range(6))
list_a.insert(0,'a')
list_s = list(range(6))
list_s.insert(0,'s')
list_r = list(range(2))
shuffle(list_r)
list_r.insert(0,'r')
list_p = list(range(3))
shuffle(list_p)
list_p.insert(0,'p')
list_x = list(range(2))
shuffle(list_x)
list_x.insert(0,'x')
list_six = list(range(2))
shuffle(list_six)
list_six.insert(0,'six')

rndm_list = [list_a, list_s, list_r, list_p, list_x, list_six] # zrandomizuj i poradi ve kterem probehne vyhodnocovani
shuffle(rndm_list) # rndm_list je neco co se ted da pozuit na dynamicke generovani testu, kdy se zacina pokazde testovat odjinud

# identifikuj kde je jaky seznam na jake pozici
s = recognize(rndm_list, 's')
a = recognize(rndm_list, 'a')
r = recognize(rndm_list, 'r')
p = recognize(rndm_list, 'p')
x = recognize(rndm_list, 'x')
six = recognize(rndm_list, 'six')

# GENEROVANI TESTU
for combo in itertools.product(*rndm_list):
    print('testova kombinace: ' ,combo)

    # VYTVORENI KONFIGURACE SPUSTENI XPLSEK03 DNS
    port = str(randrange(0,65535)) # sdileni port mezi dns a digem
    srand = randrange(0,sum(len(v) for v in data[combo[s]].values())-1) # sdileny dns server
    arand = randrange(0,sum(len(v) for v in data[combo[a]].values())-1) # sdilena hledana ip/domena
    # srand = ktery konkretni server z jednoho ze slovniku, vybranych nahodne (s[2] treba) napr. (0 = 2606:4700:4700::1111)
    # arand totez, akorat pro adresy
    
    dns = "./dns"
    dns += " -6" if combo[six] else "" 
    dns += " -x" if combo[x] else ""
    if combo[p] == 1:
        dns += " -p 53"
    elif combo[p] == 2:
        dns += " -p " + port
    dns += " -r" if combo[r] else ""
    dns += " -s "
    
    dns += list(data[combo[s]].values())[0][srand]
    dns += " "
    dns += list(data[combo[a]].values())[0][arand]
    
    # ZNAME PODMINKY RETURN KODU U XPLSEK03 DNS
    expected_return = 0 # defualtne uspech
    # bad ip/host server, bad ip/host adresa,pozadovana adresa neni platne dom jmeno, -x a neco jineho nez ip, chybny port
    if (
        list(data[combo[s]].keys()) == ['badh'] or list(data[combo[s]].keys()) == ['bad4'] or list(data[combo[s]].keys()) == ['bad6'] or 
        list(data[combo[a]].keys()) == ['badh'] or list(data[combo[a]].keys()) == ['bad4'] or list(data[combo[a]].keys()) == ['bad6'] or 
        (not combo[x] and list(data[combo[a]].keys()) != ['okh']) or 
        (combo[x] and list(data[combo[a]].keys()) == ['okh']) or 
        (combo[p] == 2 and port != 53)
        ): # chybove podminky                                
        expected_return = 1 # ocekavame chybu
        
    # SPUST DNS XPLSEK03 RESOLVER A PROZKOUMEJ NAVRATOVY KOD
    
    # kvuli problemum s pripojenim k dns serverum ktere obcas nastanou se test v pripade neuspechu jeste 2x zopakuje s nejakym malym cekanim
    for i in range(3):
        proc = subprocess.Popen(dns, stdout=subprocess.PIPE, shell=True)
        (dns_output, dns_err) = proc.communicate()
        dns_rc = proc.wait()
        if dns_rc == 2: # vratila se sitova chyba, pockej a zopakuj
            time.sleep(.250)
        else: # odpoved prisla, stop
            break
            
    generated.write(dns + '\n')

    if expected_return: # mela vyjit chyba
        if not dns_rc: # nevysla chyba
            failed.write(("[ipv6] " if (list(data[combo[s]].keys()) == ['ok6'] or combo[six]) else "") + dns + '\t\tRC: ' + str(dns_rc) + '\t\tEXPECTED: ' + ('1+' if (expected_return > 0) else '0')  + '\n')
        else: # test mel skoncit neuspechem
            passed.write('[RC: 1+] ' + dns + '\n')  
    else: # nemela vyjit chyba
        if dns_rc: # vysla chyba
            failed.write(("[ipv6] " if (list(data[combo[s]].keys()) == ['ok6'] or combo[six]) else "") + dns + '\t\tRC: ' + str(dns_rc) + '\t\tEXPECTED: ' + ('1+' if (expected_return > 0) else '0')  + '\n')          
        else: # test mel skoncit uspechem
            passed.write('[RC: 0] ' + dns + '\n')
            
    # KONEC JEDNOHO TESTU

failed.close() 
generated.close()      
passed.close()                    