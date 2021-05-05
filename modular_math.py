# -*- coding: utf-8 -*-
#
# Modular computation for ROBOT-recover
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


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, x, y = egcd(b % a, a)
    return (g, y - (b // a) * x, x)


def inverse_mod(a, n):
    g, x, _ = egcd(a, n)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % n
