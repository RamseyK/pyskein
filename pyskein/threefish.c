/*
    threefish.c
    Copyright 2008, 2009, 2010 Hagen Fürstenau <hagen@zhuliguan.net>
    Some of this code evolved from an implementation by Doug Whiting,
    which was released to the public domain.

    This file is part of PySkein.

    PySkein is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "Python.h"
#include "threefish.h"


void Threefish_256_encrypt(u64b_t *key, u64b_t *tweak, const u64b_t *p, u64b_t *out, int feed)
{
    u64b_t X0, X1, X2, X3;

    X0 = p[0] + key[0];
    X1 = p[1] + key[1] + tweak[0];
    X2 = p[2] + key[2] + tweak[1];
    X3 = p[3] + key[3];

    R256_8_rounds(0);
    R256_8_rounds(1);
    R256_8_rounds(2);
    R256_8_rounds(3);
    R256_8_rounds(4);
    R256_8_rounds(5);
    R256_8_rounds(6);
    R256_8_rounds(7);
    R256_8_rounds(8);

    if (feed) {
        out[0] = X0^p[0]; out[1] = X1^p[1]; out[2] = X2^p[2]; out[3] = X3^p[3];
    }
    else {
        out[0] = X0; out[1] = X1; out[2] = X2; out[3] = X3;
    }
}

void Threefish_256_decrypt(u64b_t *key, u64b_t *tweak, const u64b_t *c, u64b_t *out)
{
    u64b_t X0, X1, X2, X3;

    X0 = c[0]; X1 = c[1]; X2 = c[2]; X3 = c[3];

    INV_R256_8_rounds(8);
    INV_R256_8_rounds(7);
    INV_R256_8_rounds(6);
    INV_R256_8_rounds(5);
    INV_R256_8_rounds(4);
    INV_R256_8_rounds(3);
    INV_R256_8_rounds(2);
    INV_R256_8_rounds(1);
    INV_R256_8_rounds(0);

    out[0] = X0 - key[0];
    out[1] = X1 - key[1] - tweak[0];
    out[2] = X2 - key[2] - tweak[1];
    out[3] = X3 - key[3];
}


void Threefish_512_encrypt(u64b_t *key, u64b_t *tweak, const u64b_t *p, u64b_t *out, int feed)
{
    u64b_t X0, X1, X2, X3, X4, X5, X6, X7;

    X0 = p[0] + key[0];
    X1 = p[1] + key[1];
    X2 = p[2] + key[2];
    X3 = p[3] + key[3];
    X4 = p[4] + key[4];
    X5 = p[5] + key[5] + tweak[0];
    X6 = p[6] + key[6] + tweak[1];
    X7 = p[7] + key[7];

    R512_8_rounds(0);
    R512_8_rounds(1);
    R512_8_rounds(2);
    R512_8_rounds(3);
    R512_8_rounds(4);
    R512_8_rounds(5);
    R512_8_rounds(6);
    R512_8_rounds(7);
    R512_8_rounds(8);

    if (feed) {
        out[0] = X0^p[0]; out[1] = X1^p[1]; out[2] = X2^p[2]; out[3] = X3^p[3];
        out[4] = X4^p[4]; out[5] = X5^p[5]; out[6] = X6^p[6]; out[7] = X7^p[7];
    }
    else {
        out[0] = X0; out[1] = X1; out[2] = X2; out[3] = X3;
        out[4] = X4; out[5] = X5; out[6] = X6; out[7] = X7;
    }
}

void Threefish_512_decrypt(u64b_t *key, u64b_t *tweak, const u64b_t *c, u64b_t *out)
{
    u64b_t X0, X1, X2, X3, X4, X5, X6, X7;

    X0 = c[0]; X1 = c[1]; X2 = c[2]; X3 = c[3];
    X4 = c[4]; X5 = c[5]; X6 = c[6]; X7 = c[7];

    INV_R512_8_rounds(8);
    INV_R512_8_rounds(7);
    INV_R512_8_rounds(6);
    INV_R512_8_rounds(5);
    INV_R512_8_rounds(4);
    INV_R512_8_rounds(3);
    INV_R512_8_rounds(2);
    INV_R512_8_rounds(1);
    INV_R512_8_rounds(0);

    out[0] = X0 - key[0];
    out[1] = X1 - key[1];
    out[2] = X2 - key[2];
    out[3] = X3 - key[3];
    out[4] = X4 - key[4];
    out[5] = X5 - key[5] - tweak[0];
    out[6] = X6 - key[6] - tweak[1];
    out[7] = X7 - key[7];
}


void Threefish_1024_encrypt(u64b_t *key, u64b_t *tweak, const u64b_t *p, u64b_t *out, int feed)
{
    u64b_t X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, XA, XB, XC, XD, XE, XF;

    X0 = p[0x0] + key[0x0];
    X1 = p[0x1] + key[0x1];
    X2 = p[0x2] + key[0x2];
    X3 = p[0x3] + key[0x3];
    X4 = p[0x4] + key[0x4];
    X5 = p[0x5] + key[0x5];
    X6 = p[0x6] + key[0x6];
    X7 = p[0x7] + key[0x7];
    X8 = p[0x8] + key[0x8];
    X9 = p[0x9] + key[0x9];
    XA = p[0xA] + key[0xA];
    XB = p[0xB] + key[0xB];
    XC = p[0xC] + key[0xC];
    XD = p[0xD] + key[0xD] + tweak[0];
    XE = p[0xE] + key[0xE] + tweak[1];
    XF = p[0xF] + key[0xF];

    R1024_8_rounds(0);
    R1024_8_rounds(1);
    R1024_8_rounds(2);
    R1024_8_rounds(3);
    R1024_8_rounds(4);
    R1024_8_rounds(5);
    R1024_8_rounds(6);
    R1024_8_rounds(7);
    R1024_8_rounds(8);
    R1024_8_rounds(9);

    if (feed) {
        out[0x0] = X0^p[0x0]; out[0x1] = X1^p[0x1]; out[0x2] = X2^p[0x2];
        out[0x3] = X3^p[0x3]; out[0x4] = X4^p[0x4]; out[0x5] = X5^p[0x5];
        out[0x6] = X6^p[0x6]; out[0x7] = X7^p[0x7]; out[0x8] = X8^p[0x8];
        out[0x9] = X9^p[0x9]; out[0xA] = XA^p[0xA]; out[0xB] = XB^p[0xB];
        out[0xC] = XC^p[0xC]; out[0xD] = XD^p[0xD]; out[0xE] = XE^p[0xE];
        out[0xF] = XF^p[0xF];
    }
    else {
        out[0x0] = X0; out[0x1] = X1; out[0x2] = X2; out[0x3] = X3;
        out[0x4] = X4; out[0x5] = X5; out[0x6] = X6; out[0x7] = X7;
        out[0x8] = X8; out[0x9] = X9; out[0xA] = XA; out[0xB] = XB;
        out[0xC] = XC; out[0xD] = XD; out[0xE] = XE; out[0xF] = XF;
    }
}

void Threefish_1024_decrypt(u64b_t *key, u64b_t *tweak, const u64b_t *c, u64b_t *out)
{
    u64b_t X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, XA, XB, XC, XD, XE, XF;

    X0 = c[0x0]; X1 = c[0x1]; X2 = c[0x2]; X3 = c[0x3];
    X4 = c[0x4]; X5 = c[0x5]; X6 = c[0x6]; X7 = c[0x7];
    X8 = c[0x8]; X9 = c[0x9]; XA = c[0xA]; XB = c[0xB];
    XC = c[0xC]; XD = c[0xD]; XE = c[0xE]; XF = c[0xF];

    INV_R1024_8_rounds(9);
    INV_R1024_8_rounds(8);
    INV_R1024_8_rounds(7);
    INV_R1024_8_rounds(6);
    INV_R1024_8_rounds(5);
    INV_R1024_8_rounds(4);
    INV_R1024_8_rounds(3);
    INV_R1024_8_rounds(2);
    INV_R1024_8_rounds(1);
    INV_R1024_8_rounds(0);

    out[0x0] = X0 - key[0x0];
    out[0x1] = X1 - key[0x1];
    out[0x2] = X2 - key[0x2];
    out[0x3] = X3 - key[0x3];
    out[0x4] = X4 - key[0x4];
    out[0x5] = X5 - key[0x5];
    out[0x6] = X6 - key[0x6];
    out[0x7] = X7 - key[0x7];
    out[0x8] = X8 - key[0x8];
    out[0x9] = X9 - key[0x9];
    out[0xA] = XA - key[0xA];
    out[0xB] = XB - key[0xB];
    out[0xC] = XC - key[0xC];
    out[0xD] = XD - key[0xD] - tweak[0];
    out[0xE] = XE - key[0xE] - tweak[1];
    out[0xF] = XF - key[0xF];
}
