
ports = []
nexthop = []

def plookup(ip, mask)

for line in open("../config/interfaces2", 'r'):
  line = line.rstrip("\n")
  line = line.split(" ")
  ports.append([line[0], line[1], line[2]])
  print line

for line in open("../config/route", 'r'):
  line = line.rstrip("\n")
  line = line.split(" ")
