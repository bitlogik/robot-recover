# -*- coding: utf-8 -*-
#
# Scan with ROBOT-recover
# Copyright (C) 2021  Antoine Ferron
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Input  : domains.txt is a file with one domain name per line
#  or a CSV file with the first column as the domain.
# Output : CSV data to results.csv


import csv
import subprocess


fout = open("results.csv", "wb")
with open("domains.txt") as csvfile:
    domreader = csv.reader(csvfile, delimiter=",")
    for line in domreader:
        domain = line[0]
        print(domain)
        res = subprocess.run(
            ["python3", "robot_recover.py", "--csv", domain],
            stdout=subprocess.PIPE,
        )
        if res.stdout.startswith(b"VULN"):
            print("-> Vulnerable to ROBOT")
        fout.write(res.stdout)
